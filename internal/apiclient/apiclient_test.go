package apiclient

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/directory"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestDo(t *testing.T) {
	stagger, dialWait = 300*time.Millisecond, time.Second
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != profile.API()+"/enroll" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 400)
			return
		}
		w.Write(append([]byte("got "), body...))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	// The certificate is for example.com and 127.0.0.1; 192.0.2.0/24 is for
	// documentation, so nothing answers there.
	cases := []struct {
		name string
		c    Client
	}{
		{"own address", Client{Host: "127.0.0.1"}},
		{"both answer, the request goes once", Client{Host: "127.0.0.1", Relays: []string{"127.0.0.1"}}},
		{"relay first", Client{Host: "127.0.0.1", Relays: []string{"127.0.0.1"}, RelayFirst: true}},
		{"through a relay", Client{Host: "example.com", Relays: []string{"192.0.2.1", "127.0.0.1"}}},
		{"through cloudflare", Client{Host: "192.0.2.1", Cloudflare: "127.0.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			c := tc.c
			c.Port, c.Roots = port, roots
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.Do(ctx, "POST", "enroll", "tok", []byte("pin"))
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 || resp.Body != "got pin" {
				t.Fatalf("got %+v", resp)
			}
			time.Sleep(2 * stagger)
			if n := hits.Load(); n != 1 {
				t.Fatalf("the server got %d requests", n)
			}
		})
	}

	t.Run("nothing answers", func(t *testing.T) {
		c := Client{Host: "192.0.2.1", Relays: []string{"192.0.2.2"}, Port: port, Roots: roots, Cloudflare: "192.0.2.3"}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := c.Do(ctx, "GET", "profile", "tok", nil); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("built-in relays", func(t *testing.T) {
		saved := Relays
		defer func() { Relays = saved }()
		Relays = " 192.0.2.4, 127.0.0.1 "
		c := Client{Host: "example.com"}
		if got := strings.Join(c.relays(), ","); got != "192.0.2.4,127.0.0.1" {
			t.Fatalf("relays %q", got)
		}
		c.Relays = []string{"192.0.2.5"}
		if got := strings.Join(c.relays(), ","); got != "192.0.2.5" {
			t.Fatalf("the profile's relays should win: %q", got)
		}
	})

	t.Run("moved, found in the directory", func(t *testing.T) {
		pub, sign, _ := ed25519.GenerateKey(nil)
		secret := make([]byte, 32)
		blob, err := directory.Seal(directory.Entry{T: time.Now().Unix(), Host: "example.com", IPs: []string{"127.0.0.1"}}, sign, secret)
		if err != nil {
			t.Fatal(err)
		}
		gist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, blob+"\n") }))
		defer gist.Close()
		saved := []string{directory.PublicKey, directory.Secret, directory.Name, directory.GistURL}
		defer func() {
			directory.PublicKey, directory.Secret, directory.Name, directory.GistURL = saved[0], saved[1], saved[2], saved[3]
		}()
		directory.PublicKey, directory.Secret = base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(secret)
		directory.Name, directory.GistURL = "", gist.URL

		hits.Store(0)
		c := Client{Host: "192.0.2.1", Relays: []string{"192.0.2.2"}, Port: port, Roots: roots, Cloudflare: "192.0.2.3"}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, err := c.Do(ctx, "POST", "enroll", "tok", []byte("pin"))
		if err != nil || resp.Body != "got pin" || hits.Load() != 1 {
			t.Fatalf("got %+v, %v after %d requests", resp, err, hits.Load())
		}
	})
}
