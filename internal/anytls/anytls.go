// Package anytls runs AnyTLS (github.com/anytls/sing-anytls, GPLv3): TLS whose
// record sizes follow a padding scheme, so the TLS that apps do inside the
// tunnel doesn't show through as TLS-in-TLS.
package anytls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	sa "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// Config is where a client connects and its password.
type Config struct {
	// Address is the server's IP and port; Host is the certificate's name.
	Address, Host, Password string
	// RootCAs verifies the server; nil means the system's roots.
	RootCAs *x509.CertPool
}

// Client opens a stream per connection. AnyTLS needs a TLS session per stream
// in flight, so it keeps two spare ones rather than handshake for every app.
type Client struct{ c *sa.Client }

var _ bridge.Dialer = (*Client)(nil)

func NewClient(cfg Config) (*Client, error) {
	c, err := sa.NewClient(context.Background(), sa.ClientConfig{
		Password:                 cfg.Password,
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       2 * time.Minute,
		MinIdleSession:           2,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			return tlsutil.Firefox(ctx, cfg.Address, cfg.Host, cfg.RootCAs)
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (c *Client) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.c.CreateProxy(ctx, M.ParseSocksaddr(addr))
}

// DialUDP is UDP over a stream (sing's UoT v2), opened with the first datagram.
func (c *Client) DialUDP(context.Context) (bridge.PacketConn, error) {
	return &udpConn{c: c, ready: make(chan struct{})}, nil
}

func (c *Client) Close() error { return c.c.Close() }

type udpConn struct {
	c     *Client
	mu    sync.Mutex
	uc    *uot.Conn
	err   error
	ready chan struct{}
	once  sync.Once
}

func (u *udpConn) open(to netip.AddrPort) (*uot.Conn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.uc != nil || u.err != nil {
		return u.uc, u.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := u.c.c.CreateProxy(ctx, uot.RequestDestination(uot.Version))
	if err != nil {
		return nil, err
	}
	u.uc = uot.NewLazyConn(s, uot.Request{Destination: M.SocksaddrFromNetIP(to)})
	u.once.Do(func() { close(u.ready) })
	return u.uc, nil
}

func (u *udpConn) WriteTo(p []byte, to netip.AddrPort) error {
	uc, err := u.open(to)
	if err != nil {
		return err
	}
	_, err = uc.WriteTo(p, net.UDPAddrFromAddrPort(to))
	return err
}

func (u *udpConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	<-u.ready
	u.mu.Lock()
	uc, err := u.uc, u.err
	u.mu.Unlock()
	if uc == nil {
		return 0, netip.AddrPort{}, err
	}
	n, from, err := uc.ReadFrom(p)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ua, _ := from.(*net.UDPAddr)
	if ua == nil {
		return 0, netip.AddrPort{}, errors.New("anytls: datagram from a name")
	}
	return n, ua.AddrPort(), nil
}

func (u *udpConn) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err == nil {
		u.err = net.ErrClosed
	}
	u.once.Do(func() { close(u.ready) })
	if u.uc != nil {
		return u.uc.Close()
	}
	return nil
}

// Server is AnyTLS behind TLS. A wrong password gets Fallback, the website.
type Server struct {
	DialTCP  func(ctx context.Context, addr, email string) (net.Conn, error)
	DialUDP  func(ctx context.Context, email string) (net.PacketConn, error)
	Fallback func(net.Conn)

	svc atomic.Pointer[sa.Service]
}

// SetUsers replaces the logins: password to the device's email.
func (s *Server) SetUsers(passwords map[string]string) error {
	users := make([]sa.User, 0, len(passwords))
	for pass, email := range passwords {
		users = append(users, sa.User{Name: email, Password: pass})
	}
	svc, err := sa.NewService(sa.ServiceConfig{
		PaddingScheme:   padding.DefaultPaddingScheme,
		Users:           users,
		Handler:         handler{s},
		FallbackHandler: fallback{s},
		Logger:          logger.NOP(),
	})
	if err != nil {
		return err
	}
	s.svc.Store(svc)
	return nil
}

// Serve takes connections from a TLS listener until it closes.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	svc := s.svc.Load()
	if svc == nil {
		return
	}
	// The handshake and the login have to arrive promptly; streams can idle.
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if tc, ok := c.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			return
		}
	}
	svc.NewConnection(context.Background(), &firstRead{Conn: c}, M.SocksaddrFromNet(c.RemoteAddr()), nil)
}

// firstRead lifts the read deadline once the login has been read.
type firstRead struct {
	net.Conn
	done bool
}

func (f *firstRead) Read(b []byte) (int, error) {
	n, err := f.Conn.Read(b)
	if !f.done && n > 0 {
		f.done = true
		f.Conn.SetReadDeadline(time.Time{})
	}
	return n, err
}

type handler struct{ s *Server }

func (h handler) NewConnectionEx(ctx context.Context, conn net.Conn, _, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	email, _ := auth.UserFromContext[string](ctx)
	var err error
	if dest.Fqdn == uot.MagicAddress {
		err = h.udp(ctx, conn, email)
	} else {
		var up net.Conn
		if up, err = h.s.DialTCP(ctx, dest.String(), email); err == nil {
			bridge.Pipe(conn, up)
			up.Close()
		}
	}
	if onClose != nil {
		onClose(err)
	}
}

func (h handler) udp(ctx context.Context, conn net.Conn, email string) error {
	req, err := uot.ReadRequest(conn)
	if err != nil {
		return err
	}
	pc, err := h.s.DialUDP(ctx, email)
	if err != nil {
		return err
	}
	defer pc.Close()
	uc := uot.NewConn(conn, *req)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				conn.Close()
				return
			}
			if _, err := uc.WriteTo(buf[:n], from); err != nil {
				pc.Close()
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, to, err := uc.ReadFrom(buf)
		if err != nil {
			return nil
		}
		if to != nil {
			pc.WriteTo(buf[:n], to)
		}
	}
}

type fallback struct{ s *Server }

func (f fallback) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	if f.s.Fallback != nil {
		f.s.Fallback(conn)
	}
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}
