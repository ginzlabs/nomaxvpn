package vpn

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/anytls"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
)

// anyTLSServer is AnyTLS on its own port with the site's certificate. A
// wrong password gets the website.
type anyTLSServer struct {
	srv  *anytls.Server
	ln   net.Listener
	pair atomic.Pointer[tls.Certificate]
	cert string
}

func (r *Runtime) startAnyTLS() (*anyTLSServer, error) {
	a := &anyTLSServer{srv: &anytls.Server{
		DialTCP:  r.dialTCP(profile.AnyTLS),
		DialUDP:  r.dialUDP(profile.AnyTLS),
		Fallback: r.serveSite,
	}}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.pair.Load(), nil
		},
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(r.cfg.Server.Listen, strconv.Itoa(r.cfg.AnyTLSPort)), cfg)
	if err != nil {
		return nil, err
	}
	a.ln = ln
	go a.srv.Serve(ln)
	return a, nil
}

func (a *anyTLSServer) setCert(certPEM, keyPEM string) error {
	if certPEM == a.cert {
		return nil
	}
	pair, err := tlsutil.Pair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	a.pair.Store(&pair)
	a.cert = certPEM
	return nil
}

// setUsers takes each login's password to its email.
func (a *anyTLSServer) setUsers(users map[string]string) error {
	return a.srv.SetUsers(users)
}

func (a *anyTLSServer) close() { a.ln.Close() }

// serveSite answers one connection with the website, over HTTP/1.1, so a
// port that also carries a tunnel looks like the site to anyone without a login.
func (r *Runtime) serveSite(c net.Conn) {
	r.mu.Lock()
	site := r.site
	r.mu.Unlock()
	if site == nil {
		return
	}
	done := make(chan struct{})
	var once sync.Once
	srv := &http.Server{
		Handler:           site,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				once.Do(func() { close(done) })
			}
		},
	}
	srv.Serve(&oneConn{c: c})
	<-done
}

// oneConn is a listener that yields one connection.
type oneConn struct {
	c    net.Conn
	used bool
}

func (o *oneConn) Accept() (net.Conn, error) {
	if o.used {
		return nil, net.ErrClosed
	}
	o.used = true
	return o.c, nil
}

func (o *oneConn) Close() error   { return nil }
func (o *oneConn) Addr() net.Addr { return o.c.LocalAddr() }
