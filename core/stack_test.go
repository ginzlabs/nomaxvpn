package nomaxcore

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// TestStackDialer carries TCP and UDP through a userspace stack, as Windows
// runs WireGuard and the L3 engines: the far stack stands in for the server.
func TestStackDialer(t *testing.T) {
	near, nearNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	far, farNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer near.Close()
	defer far.Close()
	go wire(near, far)
	go wire(far, near)

	ln, err := farNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	pc, err := farNet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := stackDialer{nearNet, []netip.Addr{netip.MustParseAddr("10.9.0.2")}}

	c, err := d.DialTCP(ctx, "10.9.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
		t.Fatalf("tcp echo %q, %v", got, err)
	}
	c.Close()

	u, err := d.DialUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	to := netip.MustParseAddrPort("10.9.0.1:53")
	if err := u.WriteTo([]byte("ping"), to); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, from, err := u.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ping" || from != to {
			t.Errorf("udp echo %q from %v, %v", buf[:n], from, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no UDP answer")
	}
	if err := u.WriteTo([]byte("x"), netip.MustParseAddrPort("[fd00::1]:53")); err == nil {
		t.Log("IPv6 write accepted without an IPv6 address")
	}
}

// wire moves packets from one stack's interface to the other's.
func wire(from, to tun.Device) {
	bufs := [][]byte{make([]byte, 2000)}
	sizes := []int{0}
	for {
		n, err := from.Read(bufs, sizes, 0)
		if err != nil {
			return
		}
		for i := range n {
			if _, err := to.Write([][]byte{bufs[i][:sizes[i]]}, 0); err != nil {
				return
			}
		}
	}
}
