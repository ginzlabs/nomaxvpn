package anytls_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/anytls"
	"github.com/ginzlabs/nomaxvpn/internal/bridge/bridgetest"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
)

const host = "site.test"

func TestLoopback(t *testing.T) {
	must := bridgetest.Must
	certPEM, keyPEM, err := tlsutil.SelfSigned(host)
	must(t, err)
	pair, err := tlsutil.Pair(certPEM, keyPEM)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(certPEM))

	var d net.Dialer
	srv := &anytls.Server{
		DialTCP: func(ctx context.Context, addr, email string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		DialUDP: func(ctx context.Context, email string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
		Fallback: func(c net.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsite")
			}
		},
	}
	must(t, srv.SetUsers(map[string]string{"right": "d1"}))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}})
	must(t, err)
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })

	t.Run("wrong-password-gets-the-site", func(t *testing.T) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host}}}
		resp, err := c.Get("https://" + ln.Addr().String() + "/")
		must(t, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "site" {
			t.Fatalf("a browser got %q", b)
		}
	})

	t.Run("wrong-password-no-tunnel", func(t *testing.T) {
		c, err := anytls.NewClient(anytls.Config{Address: ln.Addr().String(), Host: host, Password: "wrong", RootCAs: roots})
		must(t, err)
		defer c.Close()
		conn, err := c.DialTCP(context.Background(), bridgetest.Target(t))
		if err == nil {
			io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			b, _ := io.ReadAll(conn)
			conn.Close()
			if strings.Contains(string(b), bridgetest.Hello) {
				t.Fatal("a wrong password reached the target")
			}
		}
	})

	c, err := anytls.NewClient(anytls.Config{Address: ln.Addr().String(), Host: host, Password: "right", RootCAs: roots})
	must(t, err)
	bridgetest.Run(t, profile.AnyTLS, c)
}
