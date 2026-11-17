// Command preview serves the Windows app's page on the Mac, with a pretend
// engine and server, to see the screens without a PC. PIN 123456 joins; any
// other is refused. FAIL=1 makes every protocol fail.
//
//	go run ./windows/preview   # then open http://127.0.0.1:8765
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/apiclient"
	"github.com/ginzlabs/nomaxvpn/internal/desktop"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8765", "where to serve the page")
	host := flag.String("host", "example.com", "the server the connection check tests; joining is pretend whatever it is")
	dir := flag.String("dir", filepath.Join(os.TempDir(), "nomax-preview"), "where the app keeps its files")
	flag.Parse()

	// A pretend relay, so the join screen offers the routes.
	apiclient.Relays = "203.0.113.7"
	// Like the core's, runs and steps count from the clock, so they keep growing across restarts.
	now := time.Now().UnixMilli()
	eng := &engine{fail: os.Getenv("FAIL") == "1", seq: now * 1000, run: now}
	app := desktop.New(*host, desktop.Store{Dir: *dir}, eng, desktop.Platform{
		Info:       "NoMax preview · Mac",
		Version:    "preview",
		DeviceName: "Preview PC",
		Copy:       func(string) error { return nil },
		Client:     &http.Client{Transport: fakeNet{eng}},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, desktop.Page)
	})
	mux.HandleFunc("POST /call/{method}", func(w http.ResponseWriter, r *http.Request) {
		arg, _ := io.ReadAll(r.Body)
		out, err := app.Call(r.PathValue("method"), arg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(out)
	})
	log.Printf("http://%s (files in %s)", *addr, *dir)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// fakeNet answers the app's requests: the server's API and Cloudflare's trace.
type fakeNet struct{ eng *engine }

func (f fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	switch {
	case r.URL.Host == "1.1.1.1":
		time.Sleep(400 * time.Millisecond)
		if f.eng.connected() {
			fmt.Fprint(w, "ip=198.51.100.20\nloc=GB\ncolo=LHR\n")
		} else {
			fmt.Fprint(w, "ip=203.0.113.50\nloc=DE\ncolo=FRA\n")
		}
	case r.URL.Path == profile.API()+"/enroll":
		time.Sleep(600 * time.Millisecond)
		var req struct{ PIN string }
		json.NewDecoder(r.Body).Decode(&req)
		if req.PIN != "123456" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"That PIN isn't valid. Check it and try again."}`)
			break
		}
		json.NewEncoder(w).Encode(map[string]any{"deviceToken": "preview", "profile": demoProfile()})
	case r.URL.Path == profile.API()+"/profile":
		json.NewEncoder(w).Encode(demoProfile())
	case r.URL.Path == profile.API()+"/device":
	case r.URL.Path == profile.API()+"/report":
		// Reached only through the tunnel, as on a network that blocks the server.
		time.Sleep(700 * time.Millisecond)
		if !f.eng.connected() {
			return nil, fmt.Errorf("connection refused")
		}
		var req struct{ Lines, Checks []json.RawMessage }
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(map[string]int{"new": len(req.Lines) + len(req.Checks)})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
	return w.Result(), nil
}

func demoProfile() profile.Profile {
	return profile.Profile{
		Relays:      []profile.Relay{{Address: "203.0.113.7", Country: profile.RelayCountry}},
		Exit:        &profile.ExitConf{},
		WireGuard:   profile.WireGuardConf{ServerPublicKey: "x"},
		AmneziaWG:   &profile.AmneziaConf{},
		Reality:     profile.RealityConf{MuxPort: 8443},
		Hysteria2:   &profile.HysteriaConf{Obfs: &profile.HysteriaObfs{}},
		OpenVPN:     &profile.OpenVPNConf{Cert: "x"},
		OpenConnect: &profile.OpenConnectConf{},
		TrustTunnel: &profile.TrustTunnelConf{},
		AnyTLS:      &profile.AnyTLSConf{},
		Mieru:       &profile.MieruConf{},
	}
}

// engine acts out the core's runs: in Auto, UDP is blocked and Hysteria2 fails,
// so the first TCP protocol connects.
type engine struct {
	fail bool

	mu     sync.Mutex
	events []desktop.Event
	seq    int64
	run    int64
	cancel context.CancelFunc
	on     string
	since  time.Time
}

func (e *engine) emit(proto, state, step string, order ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	e.events = append(e.events, desktop.Event{Seq: e.seq, T: time.Now().UnixMilli(), Run: e.run, Proto: proto, State: state, Step: step, Order: order})
}

func (e *engine) connected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.on != ""
}

func (e *engine) Start(profileJSON, protocol, route, preferred, wgKey string, fd int32, endpoint string) (string, error) {
	e.Cancel()
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.run++
	e.cancel, e.on = cancel, ""
	e.mu.Unlock()
	defer cancel()

	var order []string
	if protocol == "auto" || protocol == desktop.Test {
		p := demoProfile()
		if route == "exit" {
			p, _ = p.WithExit()
		}
		for _, id := range profile.Protocols {
			if profile.Offered(p, id) {
				order = append(order, id)
			}
		}
	} else {
		order = []string{protocol}
	}
	where := ""
	if route == "relay" || route == "exit" {
		where, endpoint = " through the relay", "203.0.113.7"
	}
	switch protocol {
	case "auto":
		e.emit(protocol, "start", fmt.Sprintf("Trying %d protocols%s, %s first", len(order), where, profile.Title(order[0])), order...)
	case desktop.Test:
		e.emit(protocol, "start", fmt.Sprintf("Testing %d protocols%s", len(order), where), order...)
	default:
		e.emit(protocol, "start", "Connecting with "+profile.Title(protocol)+where, order...)
	}
	works := func(p string) bool {
		return !e.fail && !strings.Contains(p, "wireguard") && p != profile.AmneziaWG && !strings.HasPrefix(p, "hysteria")
	}
	var best string
	for _, p := range order {
		e.emit(p, "trying", "Connecting over "+endpoint)
		select {
		case <-ctx.Done():
			e.emit("", "done", "Stopped")
			return "", fmt.Errorf("Stopped")
		case <-time.After(900 * time.Millisecond):
		}
		if !works(p) {
			e.emit(p, "fail", "No answer in 5 s")
			continue
		}
		e.emit(p, "ok", "Websites answer through it, 120 ms")
		if best == "" {
			best = p
		}
		if protocol != desktop.Test {
			break
		}
	}
	if best == "" {
		e.emit("", "done", "Nothing got through")
		return "", fmt.Errorf("No protocol got through.\nWireGuard: no answer in 5 s")
	}
	e.emit(best, "done", "Connected with "+profile.Title(best))
	e.mu.Lock()
	e.on, e.since = best, time.Now()
	e.mu.Unlock()
	return best, nil
}

func (e *engine) Cancel() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *engine) Stop() {
	e.Cancel()
	e.mu.Lock()
	e.on = ""
	e.mu.Unlock()
}

func (e *engine) Events(since int64) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []desktop.Event{}
	for _, ev := range e.events {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (e *engine) Stats() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.on == "" {
		return "{}"
	}
	s := time.Since(e.since).Seconds()
	return fmt.Sprintf(`{"rx":%d,"tx":%d}`, int64(s*183_000), int64(s*21_000))
}

func (e *engine) Endpoint(string) string { return "198.51.100.20" }
func (e *engine) Preferred() string      { return "" }
