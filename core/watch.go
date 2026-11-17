package nomaxcore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// The watchdog notices a tunnel that has stopped carrying traffic: apps keep
// sending and nothing comes back. Some filters let a protocol connect and
// pass the check at the start, then freeze it a little later. In Auto
// the watchdog then tries the other protocols, the one that stopped last, as
// it now counts as failed (learn.go); with
// a protocol picked, it starts that one again. It keeps trying until something
// gets through; on phones the OS tunnel holds the traffic meanwhile.
const (
	watchEvery = 5 * time.Second
	// silentFor is how long apps may go unanswered before the tunnel is checked.
	silentFor = 20 * time.Second
	// recheckAfter spaces the checks of a tunnel that passed one: each moves 256 KB.
	recheckAfter = time.Minute
	// wgStale is how old WireGuard's last handshake may get while it sends: it
	// shakes hands every 2 minutes and gives a session up after 3.
	wgStale = 3*time.Minute + 15*time.Second
	// retryFirst is the pause before trying again when nothing got through,
	// doubling up to retryMax.
	retryFirst = 15 * time.Second
	retryMax   = 2 * time.Minute
)

// sessionID changes with every Start and Stop, which ends the watchdog of the
// session before. Guarded by mu.
var sessionID int64

// tunnelSession is what the watchdog needs to start the tunnel again.
type tunnelSession struct {
	id    int64
	p     profile.Profile
	auto  bool // Auto or Test: move on to another protocol
	route string
	hide  []string // what the log masks
	wgKey string
	fd    int
	// serverIP is the server's address the app resolved; endpointIP is where
	// the running protocol connects (the server's or a relay's).
	serverIP, endpointIP string
}

func watch(s tunnelSession) {
	var (
		quiet   silence
		checked time.Time
	)
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	for range t.C {
		mu.Lock()
		if sessionID != s.id {
			mu.Unlock()
			return
		}
		proto, e := active, current()
		rx, tx := trafficLocked()
		mu.Unlock()
		now := time.Now()
		if proto == "" || quiet.observe(now, rx, tx) < silentFor || now.Sub(checked) < recheckAfter {
			continue
		}
		checked = now
		err := alive(proto, e)
		if err == nil {
			continue
		}
		if !reconnect(&s, proto, err) {
			return
		}
		quiet, checked = silence{}, time.Time{}
	}
}

// silence tracks whether what apps send gets answers.
type silence struct {
	rx, tx  int64
	started bool
	since   time.Time // the first send after the last answer; zero once answered
}

// observe takes the tunnel's byte counters and returns how long apps have
// been sending with nothing arriving.
func (s *silence) observe(now time.Time, rx, tx int64) time.Duration {
	switch {
	case !s.started || rx != s.rx:
		s.since = time.Time{}
	case tx != s.tx && s.since.IsZero():
		s.since = now
	}
	s.rx, s.tx, s.started = rx, tx, true
	if s.since.IsZero() {
		return 0
	}
	return now.Sub(s.since)
}

// alive checks the running tunnel within its budget, quietly. WireGuard's
// check is its last handshake's age, then a few pings, since a fresh
// handshake doesn't mean anything else gets through.
func alive(protocol string, e engines) error {
	if kindOf(protocol) == kindWireGuard {
		if age := time.Since(time.Unix(handshake(e.wg), 0)); age > wgStale {
			return fmt.Errorf("no handshake for %d s", int(age.Seconds()))
		}
		if e.pt == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), pingWait)
		defer cancel()
		if _, err := e.pt.pingCheck(ctx, alivePings); err != nil && !errors.Is(err, errNoPing) {
			return err
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget(protocol))
	defer cancel()
	_, err := check(ctx, 0, protocol, e)
	return overdue(ctx, err)
}

// reconnect replaces a tunnel that stopped carrying traffic, and tries again
// after a pause, longer each time, while nothing gets through. It returns
// false once the session has ended.
func reconnect(s *tunnelSession, stalled string, why error) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evMu.Lock()
	cancelRun = cancel
	evMu.Unlock()
	if s.auto {
		learnFailed(stalled)
	}
	pause := retryFirst
	for try := 1; ; try++ {
		legs := []leg{{endpoint: s.endpointIP, order: []string{stalled}}}
		if s.auto {
			if planned := planLegs(ctx, s.p, s.route, Preferred(), s.serverIP); len(planned) > 0 {
				legs = planned
			}
		}
		mu.Lock()
		if sessionID != s.id || ctx.Err() != nil {
			mu.Unlock()
			return false
		}
		stopLocked()
		var err error
		var r int64
		for i, l := range legs {
			r = newRun(s.hide)
			start := func(r int64, kind, _ string, order []string, format string, args ...any) {
				switch {
				case !s.auto:
					kind = stalled
				case i > 0:
					emitReconnect(r, kind, order, format, args...)
					return
				}
				if try == 1 {
					emitReconnect(r, kind, order, "%s stopped carrying traffic (%s). Reconnecting", profile.Title(stalled), reason(why, budget(stalled)))
				} else {
					emitReconnect(r, kind, order, "Reconnecting, try %d", try)
				}
			}
			if _, err = runLeg(ctx, r, *s, false, l, i > 0, start); err == nil {
				s.endpointIP = l.endpoint
				break
			}
			if ctx.Err() != nil {
				break
			}
			if i == len(legs)-1 {
				emit(r, "", stateInfo, "Trying again in %d s", int(pause.Seconds()))
			}
		}
		mu.Unlock()
		if err == nil {
			return true
		}
		if s.auto {
			if q, ip, ok := moved(ctx, r, s.p, s.serverIP); ok {
				s.p, s.serverIP = q, ip
				continue
			}
		}
		if !sleep(ctx, pause) {
			return false
		}
		pause = min(pause*2, retryMax)
	}
}
