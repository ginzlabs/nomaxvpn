package trusttunnel

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
	"golang.org/x/net/http2"
)

// Config is where a client connects and how it signs in.
type Config struct {
	// Address is the server's IP and port; Host is the site's name (TLS SNI).
	Address, Host      string
	Username, Password string
	// RootCAs verifies the site's certificate; nil means the system's roots.
	RootCAs *x509.CertPool
}

// Client keeps one HTTP/2 connection to the site and opens a stream per TCP
// connection, so the network sees one TLS handshake, not one per app request.
type Client struct {
	cfg  Config
	auth string
	ua   string
	t    *http2.Transport

	mu     sync.Mutex
	cc     *http2.ClientConn
	udp    *udpMux
	closed bool
}

var _ bridge.Dialer = (*Client)(nil)

func NewClient(cfg Config) *Client {
	c := &Client{
		cfg:  cfg,
		auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password)),
		ua:   runtime.GOOS + " nomax",
		t:    &http2.Transport{ReadIdleTimeout: 30 * time.Second, PingTimeout: 10 * time.Second},
	}
	c.udp = &udpMux{c: c, flows: map[uint16]*udpFlow{}}
	return c
}

// conn returns the live HTTP/2 connection, dialling one if there's none.
func (c *Client) conn(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.cc != nil && c.cc.CanTakeNewRequest() {
		return c.cc, nil
	}
	tc, err := dialTLS(ctx, c.cfg)
	if err != nil {
		return nil, err
	}
	cc, err := c.t.NewClientConn(tc)
	if err != nil {
		tc.Close()
		return nil, err
	}
	if c.cc != nil {
		c.cc.Close()
	}
	c.cc = cc
	return cc, nil
}

// dialTLS is TLS with Firefox's ClientHello, which offers HTTP/2 like a browser.
func dialTLS(ctx context.Context, cfg Config) (net.Conn, error) {
	uc, err := tlsutil.Firefox(ctx, cfg.Address, cfg.Host, cfg.RootCAs)
	if err != nil {
		return nil, err
	}
	if p := uc.ConnectionState().NegotiatedProtocol; p != "h2" {
		uc.Close()
		return nil, fmt.Errorf("the site offered %q, not HTTP/2", p)
	}
	return uc, nil
}

func (c *Client) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.connect(ctx, addr, "")
}

func (c *Client) DialUDP(ctx context.Context) (bridge.PacketConn, error) {
	return c.udp.open()
}

// Check asks the server whether this login works, over one stream.
func (c *Client) Check(ctx context.Context) error {
	s, err := c.connect(ctx, checkHost, "")
	if err != nil {
		return err
	}
	return s.Close()
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	cc := c.cc
	c.cc = nil
	c.mu.Unlock()
	c.udp.close()
	if cc != nil {
		return cc.Close()
	}
	return nil
}

// connect opens a CONNECT stream to authority.
func (c *Client) connect(ctx context.Context, authority, uaSuffix string) (*stream, error) {
	cc, err := c.conn(ctx)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	ua := c.ua
	if uaSuffix != "" {
		ua += " " + uaSuffix
	}
	req := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Host: authority},
		Host:          authority,
		Header:        http.Header{"Proxy-Authorization": {c.auth}, "User-Agent": {ua}},
		Body:          pr,
		ContentLength: -1,
	}).WithContext(sctx)
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := cc.RoundTrip(req)
		done <- result{resp, err}
	}()
	fail := func(err error) (*stream, error) {
		cancel()
		pw.Close()
		return nil, err
	}
	select {
	case <-ctx.Done():
		return fail(ctx.Err())
	case r := <-done:
		if r.err != nil {
			return fail(r.err)
		}
		if r.resp.StatusCode != http.StatusOK {
			r.resp.Body.Close()
			if r.resp.StatusCode == http.StatusProxyAuthRequired {
				return fail(errors.New("the server refused the login"))
			}
			return fail(fmt.Errorf("the server answered %d", r.resp.StatusCode))
		}
		return &stream{r: r.resp.Body, w: pw, cancel: cancel}, nil
	}
}

// stream is a CONNECT stream as a net.Conn.
type stream struct {
	r      io.ReadCloser
	w      *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
}

func (s *stream) Read(b []byte) (int, error)  { return s.r.Read(b) }
func (s *stream) Write(b []byte) (int, error) { return s.w.Write(b) }

// CloseWrite ends the upload; the download carries on.
func (s *stream) CloseWrite() error { return s.w.Close() }

func (s *stream) Close() error {
	s.once.Do(func() {
		s.w.Close()
		s.r.Close()
		s.cancel()
	})
	return nil
}

func (s *stream) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (s *stream) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (s *stream) SetDeadline(time.Time) error      { return nil }
func (s *stream) SetReadDeadline(time.Time) error  { return nil }
func (s *stream) SetWriteDeadline(time.Time) error { return nil }

// udpMux shares one _udp2 stream between every UDP association. Each one is a
// made-up source port; the server's replies name it as their destination.
type udpMux struct {
	c *Client

	mu     sync.Mutex
	s      *stream
	wmu    sync.Mutex
	flows  map[uint16]*udpFlow
	next   uint16
	closed bool
}

type udpFlow struct {
	m    *udpMux
	src  netip.AddrPort
	in   chan datagram
	done chan struct{}
	once sync.Once
}

func (m *udpMux) open() (*udpFlow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	for range 65535 {
		m.next++
		if m.next == 0 {
			m.next = 1
		}
		if m.flows[m.next] == nil {
			f := &udpFlow{m: m, src: netip.AddrPortFrom(netip.IPv4Unspecified(), m.next),
				in: make(chan datagram, 64), done: make(chan struct{})}
			m.flows[m.next] = f
			return f, nil
		}
	}
	return nil, errors.New("trusttunnel: too many UDP associations")
}

// stream returns the _udp2 stream, opening it (and its reader) if needed.
func (m *udpMux) stream() (*stream, error) {
	m.mu.Lock()
	s := m.s
	m.mu.Unlock()
	if s != nil {
		return s, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := m.c.connect(ctx, udpHost, udpHost)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.closed || m.s != nil {
		cur := m.s
		m.mu.Unlock()
		s.Close()
		if cur == nil {
			return nil, net.ErrClosed
		}
		return cur, nil
	}
	m.s = s
	m.mu.Unlock()
	go m.read(s)
	return s, nil
}

func (m *udpMux) read(s *stream) {
	buf := make([]byte, maxFrame)
	for {
		d, err := readFrame(s, buf, false)
		if err != nil {
			m.mu.Lock()
			if m.s == s {
				m.s = nil
			}
			m.mu.Unlock()
			s.Close()
			return
		}
		m.mu.Lock()
		f := m.flows[d.dst.Port()]
		m.mu.Unlock()
		if f == nil {
			continue
		}
		d.payload = append([]byte(nil), d.payload...)
		select {
		case f.in <- d:
		default: // the app isn't reading; drop like a full socket buffer
		}
	}
}

func (m *udpMux) close() {
	m.mu.Lock()
	m.closed = true
	s := m.s
	m.s = nil
	flows := m.flows
	m.flows = map[uint16]*udpFlow{}
	m.mu.Unlock()
	if s != nil {
		s.Close()
	}
	for _, f := range flows {
		f.Close()
	}
}

func (f *udpFlow) WriteTo(p []byte, to netip.AddrPort) error {
	s, err := f.m.stream()
	if err != nil {
		return err
	}
	frame := appendFrame(make([]byte, 0, 41+len(p)), datagram{src: f.src, dst: to, payload: p}, true)
	f.m.wmu.Lock()
	_, err = s.Write(frame)
	f.m.wmu.Unlock()
	if err != nil {
		// The next write opens a new stream.
		f.m.mu.Lock()
		if f.m.s == s {
			f.m.s = nil
		}
		f.m.mu.Unlock()
		s.Close()
	}
	return err
}

func (f *udpFlow) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-f.in:
		return copy(p, d.payload), d.src, nil
	case <-f.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (f *udpFlow) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.m.mu.Lock()
		if f.m.flows[f.src.Port()] == f {
			delete(f.m.flows, f.src.Port())
		}
		f.m.mu.Unlock()
	})
	return nil
}
