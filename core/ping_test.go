package nomaxcore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// osTun stands in for the OS tunnel: send is what apps send into it, got is
// what the engine hands back to them.
type osTun struct {
	send, got chan []byte
	events    chan tun.Event
	closed    chan struct{}
	once      sync.Once
}

func newOSTun() *osTun {
	return &osTun{send: make(chan []byte, 16), got: make(chan []byte, 256), events: make(chan tun.Event, 1), closed: make(chan struct{})}
}

func (o *osTun) File() *os.File           { return nil }
func (o *osTun) MTU() (int, error)        { return 1280, nil }
func (o *osTun) Name() (string, error)    { return "test", nil }
func (o *osTun) Events() <-chan tun.Event { return o.events }
func (o *osTun) BatchSize() int           { return 1 }

func (o *osTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-o.send:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-o.closed:
		return 0, os.ErrClosed
	}
}

func (o *osTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case o.got <- bytes.Clone(b[offset:]):
		default:
		}
	}
	return len(bufs), nil
}

func (o *osTun) Close() error {
	o.once.Do(func() {
		close(o.closed)
		close(o.events)
	})
	return nil
}

// echo answers the pings it reads, like the server would, and passes
// everything else back unchanged, standing in for WireGuard.
func echo(t *testing.T, pt *pingTun) {
	bufs, sizes := [][]byte{make([]byte, 2048)}, []int{0}
	for {
		n, err := pt.Read(bufs, sizes, 10)
		if err != nil {
			return
		}
		for i := range n {
			pkt := bytes.Clone(bufs[i][10 : 10+sizes[i]])
			if pkt[9] == 1 && pkt[20] == 8 {
				copy(pkt[12:16], bufs[i][10+16:10+20])
				copy(pkt[16:20], bufs[i][10+12:10+16])
				pkt[20] = 0
			}
			out := append(make([]byte, 10), pkt...)
			if _, err := pt.Write([][]byte{out}, 10); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestPingTun(t *testing.T) {
	sys := newOSTun()
	pt := newPingTun(sys, []string{"fd08::2/128", "10.8.0.2/32"}, netip.MustParseAddr("192.0.2.1"), 1280)
	defer pt.Close()
	go echo(t, pt)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got, err := pt.ping(ctx, 32); got != 32 || err != nil {
		t.Fatalf("pings back: %d %v", got, err)
	}
	if len(sys.got) != 0 {
		t.Fatalf("%d ping replies reached the OS", len(sys.got))
	}

	app := echoRequest(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("192.0.2.1"), pt.id+1, 7, 100)
	sys.send <- app
	select {
	case back := <-sys.got:
		if back[20] != 0 || !bytes.Equal(back[24:], app[24:]) {
			t.Fatal("an app's own ping came back changed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an app's own ping didn't pass through")
	}

	v6 := newPingTun(newOSTun(), []string{"fd08::2/128"}, netip.MustParseAddr("192.0.2.1"), 1280)
	defer v6.Close()
	if got, err := v6.ping(ctx, 4); got != 0 || err != errNoPing {
		t.Fatalf("a tunnel without IPv4 pinged: %d %v", got, err)
	}
}

// TestPingThroughWireGuard runs the check against a WireGuard server on a
// userspace stack, straight and through a filter that lets the handshake
// through and then drops what the client sends.
func TestPingThroughWireGuard(t *testing.T) {
	serverKey, clientKey := profile.NewWireGuardKey(), profile.NewWireGuardKey()
	serverPub, _ := profile.WireGuardPublic(serverKey)
	clientPub, _ := profile.WireGuardPublic(clientKey)

	stun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(srv.Close)
	server := listenUDP(t)
	port := server.LocalAddr().(*net.UDPAddr).Port
	server.Close()
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.8.0.2/32\n",
		hexKey(t, serverKey), port, hexKey(t, clientPub))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}

	run := func(endpoint int) (string, error) {
		pt := newPingTun(newOSTun(), []string{"10.8.0.2/32"}, netip.MustParseAddr("10.8.0.1"), 1280)
		cli := device.NewDevice(pt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		defer cli.Close()
		if err := cli.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
			hexKey(t, clientKey), hexKey(t, serverPub), endpoint)); err != nil {
			t.Fatal(err)
		}
		if err := cli.Up(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget(profile.WireGuard))
		defer cancel()
		return check(ctx, 0, profile.WireGuard, engines{wg: cli, pt: pt})
	}

	if detail, err := run(port); err != nil || !strings.Contains(detail, "of pings answered") {
		t.Fatalf("straight: %q %v", detail, err)
	}
	if detail, err := run(filter(t, port)); err == nil || !strings.Contains(err.Error(), "the handshake passed") {
		t.Fatalf("through a filter that drops data after the handshake: %q %v", detail, err)
	}
}

// filter forwards UDP to the server's port on loopback, but drops the client's
// WireGuard data (message type 4) after the first two packets of it.
func filter(t *testing.T, to int) int {
	ln := listenUDP(t)
	srv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: to}
	up, err := net.DialUDP("udp", nil, srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	var client atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			if c := client.Load(); c != nil {
				ln.WriteToUDP(buf[:n], c)
			}
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		data := 0
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(from)
			if buf[0] == 4 {
				if data++; data > 2 {
					continue
				}
			}
			up.Write(buf[:n])
		}
	}()
	return ln.LocalAddr().(*net.UDPAddr).Port
}

func listenUDP(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func hexKey(t *testing.T, b64 string) string {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k)
}
