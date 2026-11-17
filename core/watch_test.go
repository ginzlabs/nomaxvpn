package nomaxcore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestSilence(t *testing.T) {
	var s silence
	t0 := time.Unix(1000, 0)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	steps := []struct {
		sec    int
		rx, tx int64
		want   time.Duration
	}{
		{0, 100, 100, 0},
		{5, 100, 100, 0},                 // idle: nothing sent
		{10, 100, 150, 0},                // sent, unanswered from now
		{15, 100, 150, 5 * time.Second},  // still unanswered
		{30, 100, 200, 20 * time.Second}, // more sent, still nothing back
		{35, 120, 200, 0},                // an answer
		{40, 120, 260, 0},                // sent again
		{65, 120, 260, 25 * time.Second}, // and nothing back since
	}
	for _, st := range steps {
		if got := s.observe(at(st.sec), st.rx, st.tx); got != st.want {
			t.Fatalf("at %d s: silent %v, want %v", st.sec, got, st.want)
		}
	}
}

func TestReconnectEvent(t *testing.T) {
	r := newRun(nil)
	emitReconnect(r, Auto, []string{profile.Cloudflare}, "Mieru stopped carrying traffic")
	emitOrder(r, Auto, stateStart, nil, "an ordinary start")
	var got []event
	if err := json.Unmarshal([]byte(Events(0)), &got); err != nil {
		t.Fatal(err)
	}
	re, plain := got[len(got)-2], got[len(got)-1]
	if !re.Reconnect || re.State != stateStart || re.Order[0] != profile.Cloudflare || plain.Reconnect {
		t.Fatalf("events %+v %+v", re, plain)
	}
	if !strings.Contains(Events(re.Seq-1), `"reconnect":true`) || strings.Contains(Events(re.Seq), `"reconnect"`) {
		t.Fatalf("reconnect in the JSON: %s", Events(re.Seq-1))
	}
}
