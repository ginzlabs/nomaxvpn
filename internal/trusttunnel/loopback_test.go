package trusttunnel_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/bridge/bridgetest"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
	"github.com/ginzlabs/nomaxvpn/internal/trusttunnel"
)

const host = "site.test"

// TestLoopback runs the app's whole path: Xray's socks outbound into the
// bridge, the TrustTunnel client over HTTP/2, the server in front of a site,
// and out to a local target, for TCP and UDP.
func TestLoopback(t *testing.T) {
	must := bridgetest.Must
	certPEM, keyPEM, err := tlsutil.SelfSigned(host)
	must(t, err)
	pair, err := tlsutil.Pair(certPEM, keyPEM)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(certPEM))

	var d net.Dialer
	tt := &trusttunnel.Server{
		Auth: func(u, p string) (string, bool) { return "d1", u == "d1" && p == "right" },
		DialTCP: func(ctx context.Context, addr, email string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		DialUDP: func(ctx context.Context, email string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
		Site: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not here", http.StatusNotFound)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	srv := &http.Server{Handler: tt, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2", "http/1.1"}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	cfg := trusttunnel.Config{Address: ln.Addr().String(), Host: host, Username: "d1", Password: "right", RootCAs: roots}

	t.Run("check", func(t *testing.T) {
		c := trusttunnel.NewClient(cfg)
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		must(t, c.Check(ctx))
	})

	t.Run("wrong-password", func(t *testing.T) {
		bad := cfg
		bad.Password = "wrong"
		c := trusttunnel.NewClient(bad)
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := c.DialTCP(ctx, "127.0.0.1:80")
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("a wrong password should get the site's 404, got %v", err)
		}
	})

	bridgetest.Run(t, profile.TrustTunnel, trusttunnel.NewClient(cfg))
}
