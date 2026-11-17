package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// sniRouter sends TLS connections for one name to another address, prefixed
// with a PROXY header carrying the client's address, and hands the rest to
// Accept. Let's Encrypt's tls-alpn-01 checks for that name stay here.
type sniRouter struct {
	net.Listener
	name, to string
	log      *slog.Logger
	conns    chan net.Conn
	errc     chan error
}

func routeSNI(ln net.Listener, name, to string, log *slog.Logger) net.Listener {
	r := &sniRouter{Listener: ln, name: name, to: to, log: log, conns: make(chan net.Conn), errc: make(chan error, 1)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				r.errc <- err
				return
			}
			go r.route(c)
		}
	}()
	return r
}

func (r *sniRouter) Accept() (net.Conn, error) {
	select {
	case c := <-r.conns:
		return c, nil
	case err := <-r.errc:
		r.errc <- err
		return nil, err
	}
}

func (r *sniRouter) route(c net.Conn) {
	var seen bytes.Buffer
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello := peekHello(io.TeeReader(c, &seen))
	c.SetReadDeadline(time.Time{})
	pc := &replayConn{Conn: c, r: io.MultiReader(&seen, c)}
	if hello == nil || hello.ServerName != r.name || slices.Contains(hello.SupportedProtos, "acme-tls/1") {
		select {
		case r.conns <- pc:
		case <-time.After(10 * time.Second):
			c.Close()
		}
		return
	}
	defer c.Close()
	up, err := net.DialTimeout("tcp", r.to, 5*time.Second)
	if err != nil {
		r.log.Warn("sni route", "to", r.to, "err", err)
		return
	}
	defer up.Close()
	if _, err := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr()).WriteTo(up); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		io.Copy(up, pc)
		up.(*net.TCPConn).CloseWrite()
		close(done)
	}()
	io.Copy(c, up)
	c.Close()
	<-done
}

// peekHello parses the ClientHello from r, or returns nil if it isn't one.
func peekHello(r io.Reader) *tls.ClientHelloInfo {
	var hello *tls.ClientHelloInfo
	tls.Server(readOnlyConn{r: r}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = &tls.ClientHelloInfo{ServerName: h.ServerName, SupportedProtos: h.SupportedProtos}
			return nil, errStopHandshake
		},
	}).Handshake()
	return hello
}

var errStopHandshake = errors.New("peeked")

type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c readOnlyConn) Write(b []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c readOnlyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// replayConn reads the bytes peeked so far before the rest of the connection.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }
