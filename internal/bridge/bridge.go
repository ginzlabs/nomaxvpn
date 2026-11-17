// Package bridge carries the protocols Xray has no outbound for. It is a SOCKS5
// server on loopback: Xray's tun inbound sends everything to it through a
// socks outbound, and each connection or datagram goes to the protocol's client.
package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Dialer is a protocol's client.
type Dialer interface {
	// DialTCP opens a stream to addr, "host:port".
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	// DialUDP opens a datagram session that can send to any address.
	DialUDP(ctx context.Context) (PacketConn, error)
	Close() error
}

// PacketConn is one UDP association, carried however the protocol likes.
type PacketConn interface {
	WriteTo(p []byte, to netip.AddrPort) error
	// ReadFrom returns a datagram and who sent it.
	ReadFrom(p []byte) (int, netip.AddrPort, error)
	Close() error
}

// udpIdle closes an association nothing has crossed for this long.
const udpIdle = 2 * time.Minute

type Server struct {
	d  Dialer
	ln net.Listener
	wg sync.WaitGroup
	// ctx ends with Close, taking down dials still in progress: one to a
	// blocked server otherwise waits minutes for the system to give up.
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	conns map[io.Closer]struct{}
}

// Listen serves SOCKS5 on 127.0.0.1 at a free port, passing everything to d.
// The Server owns d.
func Listen(d Dialer) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{d: d, ln: ln, conns: map[io.Closer]struct{}{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close stops listening and ends every connection.
func (s *Server) Close() error {
	s.cancel()
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	s.d.Close()
	s.wg.Wait()
	return err
}

func (s *Server) track(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if s.track(c) {
				s.handle(c)
				s.untrack(c)
			}
		}()
	}
}

const (
	cmdConnect   = 1
	cmdAssociate = 3
	atypIPv4     = 1
	atypDomain   = 3
	atypIPv6     = 4
)

func (s *Server) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0}) // no authentication: only loopback can reach it
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	addr, err := readAddr(c)
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	switch req[1] {
	case cmdConnect:
		up, err := s.d.DialTCP(ctx, addr)
		if err != nil {
			c.Write([]byte{5, 5, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{5, 0, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		Pipe(c, up)
	case cmdAssociate:
		s.associate(ctx, c)
	default:
		c.Write([]byte{5, 7, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	}
}

// Pipe copies both ways until both sides end, or one has and the other is
// still going five seconds later.
func Pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Give the other direction a moment to drain what's in flight.
	t := time.AfterFunc(5*time.Second, func() { a.Close(); b.Close() })
	<-done
	t.Stop()
}

// associate relays one UDP association until its TCP control connection ends.
func (s *Server) associate(ctx context.Context, ctrl net.Conn) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ctrl.Write([]byte{5, 1, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()
	pc, err := s.d.DialUDP(ctx)
	if err != nil {
		ctrl.Write([]byte{5, 1, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer pc.Close()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{5, 0, 0, atypIPv4, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(port))
	if _, err := ctrl.Write(reply); err != nil {
		return
	}
	var (
		mu     sync.Mutex
		client *net.UDPAddr
		last   = time.Now()
	)
	touch := func() {
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}
	stop := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop); relay.Close(); pc.Close(); ctrl.Close() }) }
	defer end()
	go func() {
		io.Copy(io.Discard, ctrl)
		end()
	}()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				mu.Lock()
				idle := time.Since(last)
				mu.Unlock()
				if idle > udpIdle {
					end()
					return
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		out := make([]byte, 0, 65535+22)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				end()
				return
			}
			touch()
			mu.Lock()
			to := client
			mu.Unlock()
			if to == nil {
				continue
			}
			out = appendAddr(append(out[:0], 0, 0, 0), from)
			out = append(out, buf[:n]...)
			relay.WriteToUDP(out, to)
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Only the association's own client, on loopback, may send.
		if !from.IP.IsLoopback() || n < 4 || buf[2] != 0 {
			continue
		}
		mu.Lock()
		if client == nil {
			client = from
		}
		ok := client.Port == from.Port
		mu.Unlock()
		if !ok {
			continue
		}
		to, payload, err := parseDatagram(buf[3:n])
		if err != nil {
			continue
		}
		touch()
		if pc.WriteTo(payload, to) != nil {
			return
		}
	}
}

func readAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case atypIPv4, atypIPv6:
		b := make([]byte, map[byte]int{atypIPv4: 4, atypIPv6: 16}[t[0]])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.Unmap().String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("socks: bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// parseDatagram splits a SOCKS5 UDP datagram after RSV and FRAG. Datagrams to
// a name are dropped: Xray's tun inbound only sends to addresses.
func parseDatagram(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, errors.New("short")
	}
	n := map[byte]int{atypIPv4: 4, atypIPv6: 16}[b[0]]
	if n == 0 || len(b) < 1+n+2 {
		return netip.AddrPort{}, nil, errors.New("socks: unsupported datagram address")
	}
	ip, _ := netip.AddrFromSlice(b[1 : 1+n])
	port := binary.BigEndian.Uint16(b[1+n:])
	return netip.AddrPortFrom(ip.Unmap(), port), b[1+n+2:], nil
}

func appendAddr(b []byte, a netip.AddrPort) []byte {
	ip := a.Addr().Unmap()
	if ip.Is4() {
		v := ip.As4()
		b = append(append(b, atypIPv4), v[:]...)
	} else {
		v := ip.As16()
		b = append(append(b, atypIPv6), v[:]...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port())
}
