package desktop

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreSealsSecrets(t *testing.T) {
	flip := func(b []byte) ([]byte, error) {
		out := slices.Clone(b)
		for i := range out {
			out[i] ^= 0x5a
		}
		return out, nil
	}
	s := Store{Dir: t.TempDir(), Seal: flip, Open: flip}
	if d, err := s.Device(); d != nil || err != nil {
		t.Fatalf("before joining: %v %v", d, err)
	}
	want := Device{Host: "vpn.test", Token: "secret-token", WGKey: "secret-key", Profile: json.RawMessage(`{"host":"vpn.test"}`)}
	if err := s.SaveDevice(want); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "device.json"))
	if bytes.Contains(raw, []byte(want.Token)) || bytes.Contains(raw, []byte(want.WGKey)) {
		t.Fatalf("device.json holds a secret in the clear: %s", raw)
	}
	got, err := s.Device()
	if err != nil || got.Token != want.Token || got.WGKey != want.WGKey || got.Host != want.Host || !sameJSON(got.Profile, want.Profile) {
		t.Fatalf("read back %+v, %v", got, err)
	}
	s.ForgetDevice()
	if d, _ := s.Device(); d != nil {
		t.Fatal("device still there after forgetting it")
	}
}

func TestParseTrace(t *testing.T) {
	r := parseTrace("fl=1\nip=198.51.100.20\nts=1\nloc=GB\ncolo=LHR\n")
	if r != (IPResult{IP: "198.51.100.20", Country: "GB", Colo: "LHR"}) {
		t.Fatalf("%+v", r)
	}
}

func TestRun(t *testing.T) {
	r := startRun(Event{Run: 7, Proto: "auto", State: "start", Step: "Trying 2", Order: []string{"wireguard", "reality"}})
	for _, e := range []Event{
		{Run: 7, Proto: "wireguard", State: "trying", Step: "Connecting"},
		{Run: 7, Proto: "wireguard", State: "fail", Step: "No answer"},
		{Run: 6, Proto: "reality", State: "ok", Step: "an older run"},
		{Run: 7, Proto: "reality", State: "ok", Step: "Works"},
		{Run: 7, Proto: "reality", State: "done", Step: "Connected with Reality"},
	} {
		r.apply(e)
	}
	if r.Kind != "auto" || !r.Finished || r.Winner != "reality" || r.Headline != "Connected with Reality" {
		t.Fatalf("%+v", r)
	}
	if r.Rows[0].State != "fail" || r.Rows[1].State != "ok" || r.Rows[1].Step != "Works" || r.Rows[0].Title != "WireGuard" {
		t.Fatalf("rows %+v", r.Rows)
	}
}

// steps is an Engine that only reports the given events.
type steps struct {
	Engine
	events []Event
}

func (s *steps) Events(since int64) string {
	var out []Event
	for _, e := range s.events {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (s *steps) Stats() string { return `{"rx":0,"tx":0}` }

func (s *steps) Preferred() string { return "cloudflare|mieru" }

func TestFollowsReconnect(t *testing.T) {
	dir := t.TempDir()
	eng := &steps{}
	a := &App{store: Store{Dir: dir}, engine: eng, log: openLog(filepath.Join(dir, "log.jsonl")),
		trace: "http://127.0.0.1:1", tunnel: "on", active: "mieru"}
	state := func() (string, string) {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.tunnel, a.active
	}
	eng.events = []Event{
		{Seq: 1, Run: 9, Proto: "auto", State: "start", Step: "Mieru stopped carrying traffic. Reconnecting", Order: []string{"cloudflare", "mieru"}, Reconnect: true},
		{Seq: 2, Run: 9, Proto: "cloudflare", State: "trying", Step: "Connecting"},
	}
	a.poll()
	if tun, act := state(); tun != "connecting" || act != "" || a.run == nil || a.run.ID != 9 {
		t.Fatalf("during the reconnect: %s %q %+v", tun, act, a.run)
	}
	eng.events = append(eng.events,
		Event{Seq: 3, Run: 9, Proto: "cloudflare", State: "ok", Step: "Works"},
		Event{Seq: 4, Run: 9, Proto: "cloudflare", State: "done", Step: "Connected with Cloudflare"})
	a.poll()
	if tun, act := state(); tun != "on" || act != "cloudflare" {
		t.Fatalf("after the reconnect: %s %q", tun, act)
	}
	if got := a.store.Settings().LastGood; got != "cloudflare|mieru" {
		t.Fatalf("learned order %q", got)
	}
	a.mu.Lock()
	a.tunnel = "off"
	a.mu.Unlock()
	eng.events = append(eng.events, Event{Seq: 5, Run: 10, Proto: "auto", State: "start", Reconnect: true})
	a.poll()
	if tun, _ := state(); tun != "off" {
		t.Fatalf("a reconnect after disconnecting turned the tunnel %s", tun)
	}
}

func TestPickedProtocolWithoutTraffic(t *testing.T) {
	dir := t.TempDir()
	eng := &steps{events: []Event{
		{Seq: 1, Run: 3, Proto: "cloudflare", State: "start", Step: "Connecting with Cloudflare", Order: []string{"cloudflare"}},
		{Seq: 2, Run: 3, Proto: "cloudflare", State: "trying", Step: "Started, checking traffic"},
		{Seq: 3, Run: 3, Proto: "cloudflare", State: "fail", Step: "Connected, but no reply through the tunnel"},
		{Seq: 4, Run: 3, State: "done", Step: "Cloudflare is on, but its traffic check failed"},
	}}
	a := &App{store: Store{Dir: dir}, engine: eng, log: openLog(filepath.Join(dir, "log.jsonl")),
		trace: "http://127.0.0.1:1", tunnel: "on", active: "cloudflare"}
	a.poll()
	if got := a.State().Error; !strings.HasPrefix(got, "Cloudflare is on, but nothing comes through") {
		t.Fatalf("error %q", got)
	}
}

func TestSections(t *testing.T) {
	lines := []LogLine{
		{T: 1, State: "info", Step: "Connect with Auto"},
		{T: 2, Run: 5, Proto: "auto", State: "start", Step: "Trying 2 protocols"},
		{T: 3, State: "info", Step: "Profile updated"},
		{T: 4, Run: 5, Proto: "wireguard", State: "ok", Step: "Works"},
		{T: 5, Run: 6, Proto: "reality", State: "start", Step: "Connecting with Reality"},
	}
	s := sections(lines)
	var titles []string
	for _, sec := range s {
		titles = append(titles, sec.Title)
	}
	if strings.Join(titles, "|") != "Connecting with Reality|App|Trying 2 protocols|App" {
		t.Fatalf("titles %q", titles)
	}
	if len(s[2].Lines) != 2 {
		t.Fatalf("run 5 should keep both its lines: %+v", s[2].Lines)
	}
	text := logText("NoMax test", lines)
	if !strings.HasPrefix(text, "NoMax test\n") || !strings.Contains(text, "✓ WireGuard: Works") {
		t.Fatalf("text:\n%s", text)
	}
}

func TestLogCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	l := openLog(path)
	for range logCap + logCap/4 + 1 {
		l.app("step")
	}
	if n := len(openLog(path).snapshot()); n != logCap {
		t.Fatalf("%d lines on disk, want %d", n, logCap)
	}
}

// gate is an Engine whose Endpoint and Start wait to be let through.
type gate struct {
	Engine
	resolve, start chan struct{}
	mu             sync.Mutex
	starts, stops  int
}

func (g *gate) Endpoint(string) string {
	<-g.resolve
	return "192.0.2.1"
}

func (g *gate) Start(profileJSON, protocol, route, preferred, wgKey string, fd int32, endpoint string) (string, error) {
	g.mu.Lock()
	g.starts++
	g.mu.Unlock()
	<-g.start
	return protocol, nil
}

func (g *gate) Cancel() {}

func (g *gate) Stop() {
	g.mu.Lock()
	g.stops++
	g.mu.Unlock()
}

func (g *gate) counts() (starts, stops int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.starts, g.stops
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(what)
		}
	}
}

func TestDisconnectOvertakesStart(t *testing.T) {
	connect := func(t *testing.T) (*App, *gate) {
		dir := t.TempDir()
		g := &gate{resolve: make(chan struct{}), start: make(chan struct{})}
		a := &App{store: Store{Dir: dir}, engine: g, log: openLog(filepath.Join(dir, "log.jsonl")),
			trace: "http://127.0.0.1:1", tunnel: "off", device: &Device{Host: "vpn.test", Profile: json.RawMessage(`{}`)},
			settings: Settings{Protocol: "wireguard"}}
		a.Connect(false)
		return a, g
	}
	t.Run("while looking the server up", func(t *testing.T) {
		a, g := connect(t)
		a.Disconnect()
		close(g.resolve)
		close(g.start)
		time.Sleep(100 * time.Millisecond)
		if starts, _ := g.counts(); starts != 0 || a.Connected() {
			t.Fatalf("started %d times after the Disconnect, connected %t", starts, a.Connected())
		}
	})
	t.Run("while the core starts", func(t *testing.T) {
		a, g := connect(t)
		close(g.resolve)
		eventually(t, "Start never ran", func() bool { starts, _ := g.counts(); return starts == 1 })
		a.Disconnect()
		close(g.start)
		eventually(t, "the late tunnel stayed up", func() bool { _, stops := g.counts(); return stops == 2 })
		if a.Connected() {
			t.Fatal("shows connected after the Disconnect")
		}
	})
}
