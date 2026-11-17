package nomaxcore

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Event states. A run starts with "start" and ends with "done"; each protocol
// in it goes "trying" (once per step), then "ok" or "fail". The start's proto
// is Auto, Test or the protocol picked, with the protocols to try in order,
// and reconnect set when the core began the run itself, to replace a tunnel
// that stopped carrying traffic; a done's proto is the protocol that
// connected, empty if none did.
const (
	stateStart  = "start"
	stateTrying = "trying"
	stateOK     = "ok"
	stateFail   = "fail"
	stateInfo   = "info"
	stateDone   = "done"
)

const maxEvents = 500

type event struct {
	Seq       int64    `json:"seq"`
	T         int64    `json:"t"` // Unix milliseconds
	Run       int64    `json:"run"`
	Proto     string   `json:"proto,omitempty"`
	State     string   `json:"state"`
	Step      string   `json:"step"`
	Order     []string `json:"order,omitempty"`
	Reconnect bool     `json:"reconnect,omitempty"`
}

// The event log has its own lock: the app polls it while Start holds mu.
// seq and run start from the clock, so they keep growing when the tunnel's
// process restarts and the app asks for events after one it already has.
var (
	evMu    sync.Mutex
	events  []event
	seq     = time.Now().UnixMilli() * 1000
	run     = time.Now().UnixMilli()
	secrets *strings.Replacer
)

// newRun starts a run and masks the given secrets in every step after it.
func newRun(hide []string) int64 {
	evMu.Lock()
	defer evMu.Unlock()
	run++
	var pairs []string
	for _, s := range hide {
		if len(s) >= 6 {
			pairs = append(pairs, s, "•••")
		}
	}
	secrets = strings.NewReplacer(pairs...)
	return run
}

func currentRun() int64 {
	evMu.Lock()
	defer evMu.Unlock()
	return run
}

// emit logs a step of run r. Steps from a run that has been replaced are dropped.
func emit(r int64, proto, state, format string, args ...any) {
	emitOrder(r, proto, state, nil, format, args...)
}

// emitOrder is emit with the protocols a run will try, for its start.
func emitOrder(r int64, proto, state string, order []string, format string, args ...any) {
	add(event{Run: r, Proto: proto, State: state, Order: order}, format, args...)
}

// emitReconnect starts a run the core began itself, to replace a tunnel that
// stopped carrying traffic.
func emitReconnect(r int64, proto string, order []string, format string, args ...any) {
	add(event{Run: r, Proto: proto, State: stateStart, Order: order, Reconnect: true}, format, args...)
}

func add(e event, format string, args ...any) {
	step := fmt.Sprintf(format, args...)
	evMu.Lock()
	defer evMu.Unlock()
	if e.Run != run {
		return
	}
	if secrets != nil {
		step = secrets.Replace(step)
	}
	if len(step) > 300 {
		step = step[:300] + "…"
	}
	seq++
	e.Seq, e.T, e.Step = seq, time.Now().UnixMilli(), step
	events = append(events, e)
	if len(events) > maxEvents {
		events = append(events[:0:0], events[len(events)-maxEvents:]...)
	}
}

// Events returns the log entries after seq since, oldest first, as a JSON array
// of {seq, t, run, proto, state, step, order, reconnect}. Steps never contain
// keys or passwords.
func Events(since int64) string {
	evMu.Lock()
	defer evMu.Unlock()
	out := []event{}
	for _, e := range events {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}
