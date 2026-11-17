package nomaxcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// stackDialer dials through a userspace network stack, for the bridge. On
// Windows that stack is what WireGuard and the L3 engines run on.
type stackDialer struct {
	n *netstack.Net
	// local is the stack's addresses, at most one per IP version. UDP sockets
	// bind to them: the stack has no route for one bound to 0.0.0.0.
	local []netip.Addr
}

func (d stackDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return d.n.DialContext(ctx, "tcp", addr)
}

func (d stackDialer) DialUDP(context.Context) (bridge.PacketConn, error) {
	u := &stackUDP{in: make(chan datagram, 64), done: make(chan struct{})}
	for _, a := range d.local {
		c, err := d.n.ListenUDPAddrPort(netip.AddrPortFrom(a, 0))
		if err != nil {
			continue
		}
		u.conns = append(u.conns, c)
		go u.read(c)
	}
	if len(u.conns) == 0 {
		return nil, errors.New("the tunnel has no address for UDP")
	}
	return u, nil
}

// The engine owns the stack.
func (stackDialer) Close() error { return nil }

type datagram struct {
	b    []byte
	from netip.AddrPort
}

// stackUDP is one association over an IPv4 and an IPv6 socket on the stack.
type stackUDP struct {
	conns []*gonet.UDPConn
	in    chan datagram
	done  chan struct{}
	once  sync.Once
}

func (u *stackUDP) read(c *gonet.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		a, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		select {
		case u.in <- datagram{append([]byte(nil), buf[:n]...), a.AddrPort()}:
		case <-u.done:
			return
		}
	}
}

func (u *stackUDP) WriteTo(p []byte, to netip.AddrPort) error {
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	for _, c := range u.conns {
		if local, ok := c.LocalAddr().(*net.UDPAddr); ok && local.AddrPort().Addr().Unmap().Is4() == to.Addr().Is4() {
			_, err := c.WriteTo(p, net.UDPAddrFromAddrPort(to))
			return err
		}
	}
	return fmt.Errorf("the tunnel has no address for %s", to.Addr())
}

func (u *stackUDP) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	select {
	case d := <-u.in:
		return copy(p, d.b), d.from, nil
	case <-u.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (u *stackUDP) Close() error {
	u.once.Do(func() {
		close(u.done)
		for _, c := range u.conns {
			c.Close()
		}
	})
	return nil
}
