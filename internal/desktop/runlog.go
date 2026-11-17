package desktop

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Test is the run that tries every protocol (core's Test).
const Test = "test"

// Event is one step of a connection run from the core (core/events.go). A run
// starts with "start" (proto auto, test or the protocol picked, and Order;
// Reconnect when the core began it to replace a tunnel that stopped carrying
// traffic), each protocol goes "trying" then "ok" or "fail", and "done" names
// the protocol that connected, or none. Steps never contain keys or passwords.
type Event struct {
	Seq       int64    `json:"seq"`
	T         int64    `json:"t"`
	Run       int64    `json:"run"`
	Proto     string   `json:"proto"`
	State     string   `json:"state"`
	Step      string   `json:"step"`
	Order     []string `json:"order"`
	Reconnect bool     `json:"reconnect"`
}

// LogLine is one line of the log: a step from the core, or something the app did (run 0).
type LogLine struct {
	T     int64  `json:"t"`
	Run   int64  `json:"run"`
	Proto string `json:"proto"`
	State string `json:"state"`
	Step  string `json:"step"`
}

// Run is an Auto or Test run as the run card shows it: a row per protocol.
type Run struct {
	ID       int64    `json:"id"`
	Kind     string   `json:"kind"` // auto, test or single
	Rows     []RunRow `json:"rows"`
	Headline string   `json:"headline"`
	Finished bool     `json:"finished"`
	Winner   string   `json:"winner"`
}

type RunRow struct {
	Proto string `json:"proto"`
	Title string `json:"title"`
	State string `json:"state"` // pending, trying, ok, fail
	Step  string `json:"step"`
}

func startRun(e Event) *Run {
	kind := "single"
	switch e.Proto {
	case "auto":
		kind = "auto"
	case Test:
		kind = Test
	}
	r := &Run{ID: e.Run, Kind: kind, Headline: e.Step}
	for _, p := range e.Order {
		r.Rows = append(r.Rows, RunRow{Proto: p, Title: Title(p), State: "pending"})
	}
	return r
}

func (r *Run) apply(e Event) {
	if e.Run != r.ID {
		return
	}
	i := slices.IndexFunc(r.Rows, func(row RunRow) bool { return row.Proto == e.Proto })
	switch e.State {
	case "trying", "ok", "fail":
		if i >= 0 {
			r.Rows[i].State, r.Rows[i].Step = e.State, e.Step
		}
	case "done":
		r.Finished, r.Winner, r.Headline = true, e.Proto, e.Step
	case "info":
		switch {
		case i >= 0:
			r.Rows[i].Step = e.Step
		case !r.Finished:
			r.Headline = e.Step
		}
	}
}

// Title is a protocol's name for people.
func Title(proto string) string {
	switch proto {
	case "auto":
		return "Auto"
	case Test:
		return "Test"
	}
	return profile.Title(proto)
}

// Log is the log, kept as JSON lines in a file and capped at logCap lines.
type Log struct {
	mu    sync.Mutex
	path  string
	lines []LogLine
}

const logCap = 2000

func openLog(path string) *Log {
	l := &Log{path: path}
	if f, err := os.Open(path); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			var line LogLine
			if json.Unmarshal(s.Bytes(), &line) == nil {
				l.lines = append(l.lines, line)
			}
		}
		f.Close()
	}
	return l
}

func (l *Log) app(step string) {
	l.add(LogLine{T: time.Now().UnixMilli(), State: "info", Step: step})
}

func (l *Log) add(new ...LogLine) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, new...)
	if len(l.lines) > logCap+logCap/4 {
		l.lines = slices.Clone(l.lines[len(l.lines)-logCap:])
		l.rewrite()
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, line := range new {
		b, _ := json.Marshal(line)
		f.Write(append(b, '\n'))
	}
}

func (l *Log) rewrite() {
	var b strings.Builder
	for _, line := range l.lines {
		j, _ := json.Marshal(line)
		b.Write(j)
		b.WriteByte('\n')
	}
	os.WriteFile(l.path, []byte(b.String()), 0o600)
}

func (l *Log) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = nil
	os.Remove(l.path)
}

func (l *Log) snapshot() []LogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// Section is a run's lines, or a stretch of the app's own.
type Section struct {
	Run   int64     `json:"run"`
	Title string    `json:"title"`
	Start int64     `json:"start"`
	Lines []LogLine `json:"lines"`
}

// sections is a section per run, newest first. The core's steps for a run
// stay together even when the app logged something meanwhile; the app's lines
// get sections of their own.
func sections(lines []LogLine) []Section {
	var out []Section
	byRun := map[int64]int{}
	for _, l := range lines {
		i, ok := -1, false
		if l.Run != 0 {
			i, ok = byRun[l.Run]
		} else if n := len(out); n > 0 && out[n-1].Run == 0 {
			i, ok = n-1, true
		}
		if ok {
			out[i].Lines = append(out[i].Lines, l)
			continue
		}
		if l.Run != 0 {
			byRun[l.Run] = len(out)
		}
		out = append(out, Section{Run: l.Run, Start: l.T, Lines: []LogLine{l}})
	}
	for i := range out {
		s := &out[i]
		s.Title = "Tunnel"
		if s.Run == 0 {
			s.Title = "App"
		}
		for _, l := range s.Lines {
			if l.State == "start" {
				s.Title = l.Step
				break
			}
		}
	}
	slices.Reverse(out)
	return out
}

// Mark is a step's state as one character, for the log.
func Mark(state string) string {
	switch state {
	case "ok":
		return "✓"
	case "fail":
		return "✗"
	case "trying":
		return "…"
	case "start":
		return "▶"
	case "done":
		return "■"
	}
	return "·"
}

// logText is the log as plain text, newest run first, ready to paste into a chat.
func logText(header string, lines []LogLine) string {
	var b strings.Builder
	b.WriteString(header + "\n")
	for _, s := range sections(lines) {
		fmt.Fprintf(&b, "\n— %s · %s\n", time.UnixMilli(s.Start).Format("2 Jan 15:04"), s.Title)
		for _, l := range s.Lines {
			name := ""
			if l.Proto != "" {
				name = Title(l.Proto) + ": "
			}
			fmt.Fprintf(&b, "%s %s %s%s\n", time.UnixMilli(l.T).Format("15:04:05"), Mark(l.State), name, l.Step)
		}
	}
	return b.String()
}
