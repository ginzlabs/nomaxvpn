package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	conncheck "github.com/ginzlabs/nomaxvpn/internal/check"
)

// Send puts what the server doesn't have yet in one report: the log's lines
// and the connection checks kept here. When the server can't be reached they
// wait, and go on their own once the tunnel is up.
const (
	checksKept      = 20
	reportMaxLines  = 5000
	reportTimeout   = 45 * time.Second
	reportRetryWait = 10 * time.Minute
)

// Report is what POST {API}/report takes (internal/panel).
type Report struct {
	App    string       `json:"app"`
	Lines  []LogLine    `json:"lines"`
	Checks []SavedCheck `json:"checks"`
}

// SavedCheck is a finished connection check's report.
type SavedCheck struct {
	T    int64  `json:"t"`
	Text string `json:"text"`
}

// SendState is what the page shows about sending: the last outcome (At is
// when, in Unix ms) and whether something still waits to go.
type SendState struct {
	Sending bool   `json:"sending"`
	Message string `json:"message"`
	At      int64  `json:"at"`
	Pending bool   `json:"pending"`
}

func (s Store) Checks() []SavedCheck {
	var cs []SavedCheck
	if b, err := os.ReadFile(s.path("checks.json")); err == nil {
		json.Unmarshal(b, &cs)
	}
	return cs
}

func (s Store) AddCheck(c SavedCheck) error {
	cs := append(s.Checks(), c)
	if len(cs) > checksKept {
		cs = cs[len(cs)-checksKept:]
	}
	return s.write("checks.json", cs)
}

// keepCheck saves the connection check once it's done, if it isn't saved yet.
func (a *App) keepCheck() {
	var st struct {
		Done bool `json:"done"`
	}
	if json.Unmarshal([]byte(conncheck.State()), &st) != nil || !st.Done {
		return
	}
	text := conncheck.Text()
	a.mu.Lock()
	defer a.mu.Unlock()
	if cs := a.store.Checks(); len(cs) > 0 && cs[len(cs)-1].Text == text {
		return
	}
	a.store.AddCheck(SavedCheck{T: time.Now().UnixMilli(), Text: text})
}

// Send sends the log and checks the server doesn't have yet, in the background.
func (a *App) Send() { a.startSend(false) }

func (a *App) startSend(quiet bool) {
	a.mu.Lock()
	if a.send.Sending || a.device == nil {
		a.mu.Unlock()
		return
	}
	a.send.Sending = true
	if !quiet {
		a.send.Message, a.send.At = "Sending…", time.Now().UnixMilli()
	}
	a.mu.Unlock()
	go a.sendNow(quiet)
}

func (a *App) sendNow(quiet bool) {
	a.keepCheck()
	a.mu.Lock()
	d, since := a.device, a.settings.ReportSent
	a.mu.Unlock()
	r := Report{App: a.platform.Info}
	newest := since
	for _, l := range a.log.snapshot() {
		if l.T > since {
			r.Lines = append(r.Lines, l)
			newest = max(newest, l.T)
		}
	}
	if len(r.Lines) > reportMaxLines {
		r.Lines = r.Lines[len(r.Lines)-reportMaxLines:]
	}
	for _, c := range a.store.Checks() {
		if c.T > since {
			r.Checks = append(r.Checks, c)
			newest = max(newest, c.T)
		}
	}
	empty := d == nil || len(r.Lines)+len(r.Checks) == 0
	var err error
	if !empty {
		ctx, cancel := context.WithTimeout(context.Background(), reportTimeout)
		_, err = a.api(d.serverHost()).Report(ctx, d.Token, r)
		cancel()
	}
	var refused *APIError
	msg, sent := "", false
	a.mu.Lock()
	switch {
	case empty:
		msg = "Everything's sent already."
		a.settings.ReportPending = false
	case errors.As(err, &refused):
		msg = refused.Msg
		a.settings.ReportPending = false
	case err != nil:
		msg = "Can't reach NoMax right now. It's saved here and goes by itself once you're connected."
		a.settings.ReportPending = true
	default:
		msg, sent = "Sent to NoMax. Thank you!", true
		a.settings.ReportSent, a.settings.ReportPending = newest, false
	}
	a.store.SaveSettings(a.settings)
	a.send.Sending = false
	// A retry in the background only speaks up once it got through.
	if !quiet || sent {
		a.send.Message, a.send.At = msg, time.Now().UnixMilli()
	}
	a.mu.Unlock()
}

// retrySend sends what's waiting soon after the app starts, then now and then;
// up also tries once the tunnel connects.
func (a *App) retrySend() {
	time.Sleep(5 * time.Second)
	a.sendIfPending()
	for range time.Tick(reportRetryWait) {
		a.sendIfPending()
	}
}

func (a *App) sendIfPending() {
	a.mu.Lock()
	pending := a.settings.ReportPending
	a.mu.Unlock()
	if pending {
		a.startSend(true)
	}
}
