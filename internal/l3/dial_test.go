package l3

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xen0bit/veepin/anyconnect"
)

// Auto gives each protocol a few seconds, so a server that takes the TCP
// connection and never answers TLS must not hold OpenConnect past ctx.
func TestOpenConnectDialStopsAtDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			defer c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = anyconnect.Dial(ctx, anyconnect.Config{
		Server: "vpn.example", Address: "127.0.0.1", Port: port, Username: "u", Password: "p",
	})
	if err == nil {
		t.Fatal("dial worked against a silent server")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("dial took %s, want about 300 ms", took)
	}
}

// ocserv with camouflage answers 404 unless a connection's first request
// carries the secret as its query.
func TestOpenConnectSendsSecret(t *testing.T) {
	urls := make(chan string, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urls <- r.RequestURI
		http.NotFound(w, r)
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	for _, secret := range []string{"", "s3cret"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, err := anyconnect.Dial(ctx, anyconnect.Config{
			Server: "m.example", Address: "127.0.0.1", Port: port, Username: "u", Password: "p",
			Secret: secret, Insecure: true, TUN: noTUN{},
		})
		cancel()
		if err == nil {
			t.Fatal("dial worked against a 404")
		}
		want := "/"
		if secret != "" {
			want += "?" + secret
		}
		select {
		case got := <-urls:
			if got != want {
				t.Fatalf("first request for %q, want %q", got, want)
			}
		default:
			t.Fatalf("no request reached the server: %v", err)
		}
	}
}

type noTUN struct{}

func (noTUN) Read([]byte) (int, error)    { select {} }
func (noTUN) Write(p []byte) (int, error) { return len(p), nil }
func (noTUN) Close() error                { return nil }
func (noTUN) Name() string                { return "test" }
