package l3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/xen0bit/veepin/anyconnect"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/openvpn"
)

const (
	dialTimeout   = 15 * time.Second
	livenessEvery = 15 * time.Second
)

// Package l3 runs OpenVPN or OpenConnect over a packet tunnel. Their servers
// give the device an address of their own, so a NAT translates between it and
// the tunnel interface's address (the WireGuard one the app configured). A
// session that dies is dialled again on the same interface.
type Tunnel struct {
	protocol   string
	p          profile.Profile
	endpointIP string
	dev        *nat

	mu     sync.Mutex
	sess   client.Session
	closed bool
	redial chan struct{}
	done   chan struct{}
}

// Start dials protocol on dev, whose interface has the profile's WireGuard
// addresses, giving up at ctx's deadline (or after dialTimeout). endpointIP is
// the server's address, resolved before the tunnel came up. The Tunnel owns
// dev from then on, even when Start fails.
func Start(ctx context.Context, dev tun.Device, p profile.Profile, protocol, endpointIP string) (*Tunnel, error) {
	switch {
	case protocol == profile.OpenVPN && p.OpenVPN == nil, protocol == profile.OpenConnect && p.OpenConnect == nil:
		return nil, fmt.Errorf("the server doesn't offer %s", protocol)
	}
	local4, local6, err := tunnelAddrs(p.WireGuard.Address)
	if err != nil {
		dev.Close()
		return nil, err
	}
	l := &Tunnel{protocol: protocol, p: p, endpointIP: endpointIP, dev: newNAT(dev, local4, local6),
		redial: make(chan struct{}, 1), done: make(chan struct{})}
	sess, err := l.dial(ctx)
	if err != nil {
		l.dev.close()
		return nil, err
	}
	l.sess = sess
	go l.keep()
	return l, nil
}

func (l *Tunnel) dial(ctx context.Context) (client.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	var (
		sess client.Session
		res  client.Result
		err  error
	)
	switch l.protocol {
	case profile.OpenVPN:
		o := l.p.OpenVPN
		sess, res, err = openvpn.Dial(ctx, openvpn.Config{
			Remote: l.endpointIP, Port: o.Port, CA: []byte(o.CA), Cert: []byte(o.Cert), Key: []byte(o.Key),
			TLSCrypt: []byte(o.TLSCrypt), Cipher: "AES-256-GCM", TUN: l.dev, Logger: log,
		})
	case profile.OpenConnect:
		c := l.p.OpenConnect
		sess, res, err = anyconnect.Dial(ctx, anyconnect.Config{
			Server: c.Server, Address: l.endpointIP, Port: c.Port, Username: c.Username, Password: c.Password,
			Secret: c.Secret, TUN: l.dev, Logger: log,
		})
	}
	if err != nil {
		return nil, err
	}
	l.dev.setRemote(res.AssignedIP, res.AssignedIP6)
	return sess, nil
}

// keep dials again whenever the session ends, stops answering, or bump asks.
func (l *Tunnel) keep() {
	defer close(l.done)
	for {
		l.mu.Lock()
		sess := l.sess
		l.mu.Unlock()
		ended := make(chan struct{})
		go func() {
			sess.Wait(context.Background())
			close(ended)
		}()
		tick := time.NewTicker(livenessEvery)
	watch:
		for {
			select {
			case <-ended:
				break watch
			case <-l.redial:
				break watch
			case <-tick.C:
				if p, ok := sess.(interface{ Probe(context.Context) error }); ok && p.Probe(context.Background()) != nil {
					break watch
				}
			}
		}
		tick.Stop()
		sess.Close()
		for wait := time.Second; ; wait = min(wait*2, 30*time.Second) {
			l.mu.Lock()
			if l.closed {
				l.mu.Unlock()
				return
			}
			l.mu.Unlock()
			if s, err := l.dial(context.Background()); err == nil {
				l.mu.Lock()
				l.sess = s
				closed := l.closed
				l.mu.Unlock()
				if closed {
					s.Close()
					return
				}
				break
			}
			time.Sleep(wait)
		}
	}
}

// Bump reconnects after a network change; the old socket may be gone.
func (l *Tunnel) Bump() {
	select {
	case l.redial <- struct{}{}:
	default:
	}
}

// Close ends the session and closes the device.
func (l *Tunnel) Close() {
	l.mu.Lock()
	l.closed = true
	sess := l.sess
	l.mu.Unlock()
	sess.Close()
	l.Bump()
	<-l.done
	l.dev.close()
}

// Traffic is the bytes received and sent through the tunnel so far.
func (l *Tunnel) Traffic() (rx, tx int64) { return l.dev.rx.Load(), l.dev.tx.Load() }

// Address is the IPv4 address the server assigned, "" before it has.
func (l *Tunnel) Address() string {
	if r := l.dev.remote.Load(); r != nil && r[0] != nil {
		return r[0].String()
	}
	return ""
}

// Check asks the session for one round trip (OpenVPN's ping, AnyConnect's
// DPD), proving packets still flow after the login.
func (l *Tunnel) Check(ctx context.Context) error {
	l.mu.Lock()
	sess := l.sess
	l.mu.Unlock()
	if p, ok := sess.(interface{ Probe(context.Context) error }); ok {
		return p.Probe(ctx)
	}
	return nil
}

func tunnelAddrs(cidrs []string) (v4, v6 net.IP, err error) {
	for _, c := range cidrs {
		ip, _, err := net.ParseCIDR(c)
		if err != nil {
			return nil, nil, err
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4 = ip4
		} else {
			v6 = ip
		}
	}
	if v4 == nil {
		return nil, nil, errors.New("profile has no IPv4 tunnel address")
	}
	return v4, v6, nil
}

// tunOffset leaves room for the 4-byte address family header darwin's utun adds.
const tunOffset = 16

// nat is the dataplane.Device the clients read and write. Reads are packets
// from apps, sent with the tunnel interface's address as source; writes are
// packets for apps, addressed to the server-assigned address.
type nat struct {
	dev            tun.Device
	local4, local6 net.IP
	remote         atomic.Pointer[[2]net.IP] // assigned IPv4, IPv6 (nil if none)
	rx, tx         atomic.Int64

	rmu     sync.Mutex
	bufs    [][]byte
	sizes   []int
	pending [][]byte

	wmu  sync.Mutex
	wbuf []byte
}

func newNAT(dev tun.Device, local4, local6 net.IP) *nat {
	n := &nat{dev: dev, local4: local4, local6: local6, wbuf: make([]byte, tunOffset+65535)}
	batch := max(dev.BatchSize(), 1)
	n.bufs = make([][]byte, batch)
	for i := range n.bufs {
		n.bufs[i] = make([]byte, tunOffset+65535)
	}
	n.sizes = make([]int, batch)
	return n
}

func (n *nat) setRemote(v4, v6 net.IP) {
	n.remote.Store(&[2]net.IP{v4.To4(), v6})
}

func (n *nat) Read(buf []byte) (int, error) {
	n.rmu.Lock()
	defer n.rmu.Unlock()
	for {
		if len(n.pending) == 0 {
			count, err := n.dev.Read(n.bufs, n.sizes, tunOffset)
			if err != nil {
				return 0, err
			}
			for i := range count {
				n.pending = append(n.pending, n.bufs[i][tunOffset:tunOffset+n.sizes[i]])
			}
			continue
		}
		pkt := n.pending[0]
		n.pending = n.pending[1:]
		r := n.remote.Load()
		if r == nil || !rewrite(pkt, true, n.local4, r[0], n.local6, r[1]) {
			continue
		}
		n.tx.Add(int64(len(pkt)))
		return copy(buf, pkt), nil
	}
}

func (n *nat) Write(pkt []byte) (int, error) {
	r := n.remote.Load()
	if r == nil || len(pkt) > 65535 {
		return len(pkt), nil
	}
	n.wmu.Lock()
	defer n.wmu.Unlock()
	b := n.wbuf[:tunOffset+len(pkt)]
	copy(b[tunOffset:], pkt)
	if !rewrite(b[tunOffset:], false, r[0], n.local4, r[1], n.local6) {
		return len(pkt), nil
	}
	if _, err := n.dev.Write([][]byte{b}, tunOffset); err != nil {
		return 0, err
	}
	n.rx.Add(int64(len(pkt)))
	return len(pkt), nil
}

// Close is a no-op so a session's teardown leaves the interface for the next dial.
func (n *nat) Close() error { return nil }

func (n *nat) Name() string { return "nomax" }

func (n *nat) close() { n.dev.Close() }
