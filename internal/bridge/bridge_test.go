package bridge

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// hanging dials like a client whose server is blocked: nothing comes back
// until the context ends.
type hanging struct{ dialing chan struct{} }

func (h hanging) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	h.dialing <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (hanging) DialUDP(context.Context) (PacketConn, error) { return nil, net.ErrClosed }
func (hanging) Close() error                                { return nil }

func TestCloseEndsDials(t *testing.T) {
	h := hanging{dialing: make(chan struct{}, 1)}
	s, err := Listen(h)
	if err != nil {
		t.Fatal(err)
	}
	socks, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port())), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	go socks.Dial("tcp", "192.0.2.1:443")
	select {
	case <-h.dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge never dialed")
	}
	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for a dial to a blocked server")
	}
}
