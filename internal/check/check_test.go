package check

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/vpn"
)

func TestPortsMatchServer(t *testing.T) {
	want := []int{vpn.RealityMuxPort, vpn.AnyTLSPort, vpn.MieruPort}
	for i, p := range want {
		if otherPorts[i] != p {
			t.Fatalf("otherPorts = %v, server opens %v", otherPorts, want)
		}
	}
}

func TestDownloadStall(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(downloadSize))
		w.Write(make([]byte, 16<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state, detail := download(ctx, srv.Client(), srv.URL)
	if state != Fail || !strings.HasPrefix(detail, "Stopped after 16 KB") {
		t.Fatalf("stalled download: %s %q", state, detail)
	}
}

func TestDownload(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, downloadSize))
	}))
	defer srv.Close()
	if state, detail := download(context.Background(), srv.Client(), srv.URL); state != OK || !strings.HasPrefix(detail, "64 KB in") {
		t.Fatalf("download: %s %q", state, detail)
	}
}

// A server that only serves one name still answers a handshake for another,
// which tells a blocked name from a blocked address.
func TestHandshakeUnderAnotherName(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler()).TLS.Certificates[0]
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName != "site.test" {
				return nil, errors.New("unknown name")
			}
			return &cert, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	ctx := context.Background()
	if state, detail := handshake(ctx, ln.Addr().String(), otherName, true); state != OK || !strings.HasPrefix(detail, "The server answered") {
		t.Fatalf("another name: %s %q", state, detail)
	}
	if state, detail := handshake(ctx, ln.Addr().String(), otherName, false); state != Fail || !strings.HasPrefix(detail, "Refused by the server") {
		t.Fatalf("strict handshake: %s %q", state, detail)
	}
}

func TestReachRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if state, detail := reach(context.Background(), "tcp", addr); state != Fail || detail != "Refused" {
		t.Fatalf("closed port: %s %q", state, detail)
	}
}

func TestVerdict(t *testing.T) {
	all := func(states map[string]string) Report {
		rep := Report{Host: "site.test", Steps: append([]Step(nil), plan...)}
		for i := range rep.Steps {
			rep.Steps[i].State = OK
			if s, ok := states[rep.Steps[i].ID]; ok {
				rep.Steps[i].State = s
			}
		}
		return rep
	}
	for _, c := range []struct {
		states map[string]string
		want   []string
	}{
		{nil, []string{"reachable from this network", "send this report"}},
		{map[string]string{"apple": Fail, "yandex": Fail, "web": Fail}, []string{"doesn't seem to be online"}},
		{map[string]string{"tcp": Fail, "upcloud": Fail}, []string{"blocks our hosting provider", "route through Cloudflare works"}},
		{map[string]string{"tcp": Fail, "web": Fail}, []string{"blocks our server's address", "Cloudflare is blocked too"}},
		{map[string]string{"tls": Fail}, []string{"blocks our server's name, site.test"}},
		{map[string]string{"download": Fail}, []string{"after the first few kilobytes"}},
		{map[string]string{"udp": Fail}, []string{"UDP to it is blocked"}},
		{map[string]string{"dns": Fail}, []string{"DNS gives a wrong address"}},
	} {
		v := verdict(all(c.states))
		for _, w := range c.want {
			if !strings.Contains(v, w) {
				t.Errorf("%v: verdict %q lacks %q", c.states, v, w)
			}
		}
	}
}

// Run against a real server: NOMAX_CHECK=example.com go test -run Live -v ./internal/check
func TestLive(t *testing.T) {
	host := os.Getenv("NOMAX_CHECK")
	if host == "" {
		t.Skip("set NOMAX_CHECK to a server's name")
	}
	Start(host, "go test")
	for !latest().report().Done {
		time.Sleep(200 * time.Millisecond)
	}
	t.Log("\n" + Text())
}

func TestText(t *testing.T) {
	rep := Report{Host: "site.test", App: "NoMax 1 · Test", Started: 0, Done: true, Verdict: "Fine.",
		Steps: []Step{{ID: "dns", Group: "DNS", Title: "Your network's DNS", State: OK, Detail: "192.0.2.1"}}}
	got := rep.Text()
	for _, w := range []string{"NoMax connection check, 1 Jan 1970 00:00 UTC", "NoMax 1 · Test", "Server: site.test", "Fine.", "DNS\n  ✓ Your network's DNS: 192.0.2.1"} {
		if !strings.Contains(got, w) {
			t.Errorf("text lacks %q:\n%s", w, got)
		}
	}
}
