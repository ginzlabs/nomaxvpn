package nomaxcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/desktop"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TestLiveWindows joins the real server with NOMAX_LIVE_PIN (a reusable PIN,
// such as App Review's), connects with every protocol through the Wintun
// adapter, checks that websites see the server, then removes the device. It
// needs administrator rights and wintun.dll next to the test binary; CI runs it.
func TestLiveWindows(t *testing.T) {
	pin, host := os.Getenv("NOMAX_LIVE_PIN"), os.Getenv("NOMAX_LIVE_HOST")
	if pin == "" || host == "" {
		t.Skip("NOMAX_LIVE_PIN and NOMAX_LIVE_HOST not set")
	}
	key := profile.NewWireGuardKey()
	pub, _ := profile.WireGuardPublic(key)
	api := desktop.API{Host: host}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	token, prof, err := api.Enroll(ctx, pin, "Windows CI", pub)
	cancel()
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	t.Cleanup(func() {
		Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := api.DeleteDevice(ctx, token); err != nil {
			t.Errorf("removing the device: %v", err)
		}
	})
	var p profile.Profile
	if err := json.Unmarshal(prof, &p); err != nil {
		t.Fatal(err)
	}
	endpoint, err := ResolveHost(host)
	if err != nil {
		t.Fatal(err)
	}
	before := trace(t)
	t.Logf("without the tunnel websites see %s", before)

	for _, proto := range append(autoOrder(p, ""), Auto) {
		t.Run(proto, func(t *testing.T) {
			defer Stop()
			since := lastSeq()
			used, err := Start(string(prof), proto, RouteDirect, "", key, -1, endpoint)
			if err == nil && proto != Auto {
				err = waitDone(since, budget(proto)+15*time.Second)
			}
			logEvents(t, since)
			if err != nil {
				t.Fatalf("%s: %v", proto, err)
			}
			if ip := trace(t); ip != endpoint {
				t.Fatalf("through %s websites see %s, want the server's %s", used, ip, endpoint)
			}
		})
	}
	// Through each relay, traffic still leaves from the server; with the
	// exit route it leaves from the relay.
	for _, r := range p.Relays {
		for _, c := range []struct{ route, want string }{{RouteRelay, endpoint}, {RouteExit, r.Address}} {
			t.Run(c.route+" "+r.Address, func(t *testing.T) {
				defer Stop()
				since := lastSeq()
				one := p
				one.Relays = []profile.Relay{r}
				b, _ := json.Marshal(one)
				used, err := Start(string(b), Auto, c.route, "", key, -1, endpoint)
				logEvents(t, since)
				if err != nil {
					t.Fatalf("%s: %v", c.route, err)
				}
				if ip := trace(t); ip != c.want {
					t.Fatalf("through %s websites see %s, want %s", used, ip, c.want)
				}
			})
		}
	}
	if ip := trace(t); ip != before {
		t.Errorf("after disconnecting websites see %s, want %s", ip, before)
	}

	// Disconnecting while Auto or Test is still trying protocols has to leave
	// the network as it was, DNS included.
	for _, c := range []struct {
		mode  string
		after time.Duration
	}{{Auto, 500 * time.Millisecond}, {Auto, 1500 * time.Millisecond}, {Auto, 3 * time.Second},
		{Test, 5 * time.Second}, {Test, 9 * time.Second}, {Test, 14 * time.Second}, {Test, 20 * time.Second}} {
		t.Run(fmt.Sprintf("disconnect %s after %s", c.mode, c.after), func(t *testing.T) {
			since := lastSeq()
			done := make(chan struct{})
			go func() {
				Start(string(prof), c.mode, RouteDirect, "", key, -1, endpoint)
				close(done)
			}()
			time.Sleep(c.after)
			Cancel()
			Stop()
			<-done
			logEvents(t, since)
			if strings.Contains(Events(since), "left behind") {
				t.Logf("LEFT BEHIND: the adapter kept routes or DNS after its engine stopped")
			}
			if _, err := net.LookupHost("example.com"); err != nil {
				t.Fatalf("DNS after disconnecting: %v", err)
			}
			if ip := trace(t); ip != before {
				t.Fatalf("after disconnecting websites see %s, want %s", ip, before)
			}
		})
	}

	// Connecting again straight after a session that carried traffic has
	// failed with every protocol, then worked minutes later.
	t.Run("Auto again after a session", func(t *testing.T) {
		since := lastSeq()
		used, err := Start(string(prof), Auto, RouteDirect, profile.Hysteria2, key, -1, endpoint)
		if err != nil {
			logEvents(t, since)
			t.Fatalf("first connect: %v", err)
		}
		pull(t, 20<<20)
		Stop()
		t.Logf("after disconnecting %s: %s", used, leftover())
		again, err := Start(string(prof), Auto, RouteDirect, used, key, -1, endpoint)
		logEvents(t, since)
		defer Stop()
		if err != nil {
			t.Fatalf("Auto right after disconnecting: %v", err)
		}
		if again != used {
			t.Errorf("Auto right after a %s session took %s", used, again)
		}
		if ip := trace(t); ip != endpoint {
			t.Fatalf("through %s websites see %s, want the server's %s", again, ip, endpoint)
		}
	})
}

// TestWindowsDisconnectWhileWaiting disconnects while WireGuard waits for a
// handshake that never comes, as it does on networks that drop WireGuard,
// where doing so left the PC without DNS. Hysteria2 fails first, as it did
// there. The server is an
// address nothing answers on. It needs administrator rights and wintun.dll
// next to the test binary; CI runs it.
func TestWindowsDisconnectWhileWaiting(t *testing.T) {
	if os.Getenv("NOMAX_WINTUN") == "" {
		t.Skip("NOMAX_WINTUN not set")
	}
	pub, _ := profile.WireGuardPublic(profile.NewWireGuardKey())
	prof, _ := json.Marshal(profile.Profile{
		Host:      "vpn.test",
		WireGuard: profile.WireGuardConf{Port: 51820, ServerPublicKey: pub, Address: []string{"10.8.0.7/32"}, DNS: profile.DNS, MTU: 1280},
		Hysteria2: &profile.HysteriaConf{Port: 443, Auth: "x"},
	})
	const nowhere = "192.0.2.1" // TEST-NET-1
	before := trace(t)
	for _, c := range []struct {
		first string
		after time.Duration
	}{{"", 0}, {"", time.Second}, {"", 2500 * time.Millisecond},
		{profile.Hysteria2, 0}, {profile.Hysteria2, time.Second}, {profile.Hysteria2, 2500 * time.Millisecond}} {
		t.Run(fmt.Sprintf("%s into the wait, %q first", c.after, c.first), func(t *testing.T) {
			since := lastSeq()
			done := make(chan struct{})
			go func() {
				Start(string(prof), Auto, RouteDirect, c.first, profile.NewWireGuardKey(), -1, nowhere)
				close(done)
			}()
			waiting := waitStep(since, profile.WireGuard, "Waiting for the handshake", time.Minute)
			time.Sleep(c.after)
			Cancel()
			<-done
			// What a NoMax without Stop's cleanup would have been left with.
			state := leftover()
			_, dnsErr := net.LookupHost("example.com")
			ip, traceErr := traceIP()
			Stop()
			logEvents(t, since)
			t.Logf("once the run stopped: %s", state)
			if !waiting {
				t.Fatal("WireGuard never waited for its handshake")
			}
			if dnsErr != nil {
				t.Errorf("DNS once the run stopped: %v", dnsErr)
			}
			if traceErr != nil || ip != before {
				t.Errorf("once the run stopped websites see %q (%v), want %s", ip, traceErr, before)
			}
			if ev := Events(since); strings.Contains(ev, "left behind") || strings.Contains(ev, "left running") {
				t.Errorf("Stop found routes, DNS or an engine left behind")
			}
			if _, err := net.LookupHost("example.com"); err != nil {
				t.Fatalf("DNS after Stop: %v", err)
			}
			if ip := trace(t); ip != before {
				t.Fatalf("after Stop websites see %s, want %s", ip, before)
			}
		})
	}
}

// waitStep waits for proto to reach step in the events after since.
func waitStep(since int64, proto, step string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		var evs []event
		json.Unmarshal([]byte(Events(since)), &evs)
		for _, e := range evs {
			if e.Proto == proto && e.Step == step {
				return true
			}
			if e.State == stateDone {
				return false
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// leftover describes the engines still set and every NoMax adapter's routes and DNS.
func leftover() string {
	mu.Lock()
	s := fmt.Sprintf("engines: wireguard %t, xray %t, bridge %t, l3 %t, active %q", wg != nil, xr != nil, br != nil, tn != nil, active)
	mu.Unlock()
	runningMu.Lock()
	s += fmt.Sprintf(", xray instances %d", len(running))
	runningMu.Unlock()
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return s + "; adapters: " + err.Error()
	}
	for _, a := range ifs {
		if !strings.HasPrefix(a.FriendlyName(), TunName) {
			continue
		}
		dns, _ := a.LUID.DNS()
		routes, defaults := 0, 0
		for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			rows, _ := winipcfg.GetIPForwardTable2(f)
			for i := range rows {
				if rows[i].InterfaceLUID == a.LUID {
					routes++
					if rows[i].DestinationPrefix.Prefix().Bits() == 0 {
						defaults++
					}
				}
			}
		}
		s += fmt.Sprintf("; adapter %q status %d: %d routes (%d default), DNS %v", a.FriendlyName(), a.OperStatus, routes, defaults, dns)
	}
	return s
}

// pull downloads n bytes through whatever route the system has.
func pull(t *testing.T, n int) {
	t.Helper()
	c := &http.Client{Timeout: time.Minute}
	resp, err := c.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", n))
	if err != nil {
		t.Logf("download: %v", err)
		return
	}
	got, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	t.Logf("downloaded %d KB (%v)", got>>10, err)
}

func lastSeq() int64 {
	evMu.Lock()
	defer evMu.Unlock()
	return seq
}

// waitDone waits for the run's last step: the traffic check of a protocol picked by hand.
func waitDone(since int64, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		var evs []event
		json.Unmarshal([]byte(Events(since)), &evs)
		for _, e := range evs {
			if e.State == stateDone {
				if e.Proto == "" {
					return errorString(e.Step)
				}
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errorString("no result in " + wait.String())
}

type errorString string

func (e errorString) Error() string { return string(e) }

func logEvents(t *testing.T, since int64) {
	var evs []event
	json.Unmarshal([]byte(Events(since)), &evs)
	for _, e := range evs {
		t.Logf("%s %s %s", e.State, e.Proto, e.Step)
	}
}

// trace is the IPv4 address Cloudflare sees this machine's traffic come from.
// A kept-alive connection from before the tunnel would still leave outside it.
func trace(t *testing.T) string {
	t.Helper()
	ip, err := traceIP()
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	return ip
}

func traceIP() (string, error) {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	var last error
	for range 3 {
		resp, err := c.Get("https://1.1.1.1/cdn-cgi/trace")
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for line := range strings.SplitSeq(string(b), "\n") {
			if ip, ok := strings.CutPrefix(line, "ip="); ok {
				return ip, nil
			}
		}
		last = errorString("no ip in the trace")
	}
	return "", last
}
