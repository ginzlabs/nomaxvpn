// Package bridgetest has the loopback pieces the bridged protocols' tests share:
// a target site, a UDP echo, and the app's path through Xray and the bridge.
package bridgetest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
	"golang.org/x/net/proxy"
)

const Hello = "hello through the bridge"

// Target serves Hello at / and 256 KB at /big. It returns host:port.
func Target(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Must(t, err)
	big := bytes.Repeat([]byte{'x'}, 256<<10)
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write(big)
			return
		}
		io.WriteString(w, Hello)
	})}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

// Echo answers every datagram with itself.
func Echo(t *testing.T) *net.UDPAddr {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	Must(t, err)
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// Run checks d the way the app uses it: TCP from Xray's socks outbound through
// the bridge (a page and the 256 KB check), and UDP through a SOCKS5 association.
func Run(t *testing.T, protocol string, d bridge.Dialer) {
	target, echo := Target(t), Echo(t)
	b, err := bridge.Listen(d)
	Must(t, err)
	t.Cleanup(func() { b.Close() })

	t.Run("tcp-through-xray", func(t *testing.T) {
		socks := FreeTCP(t)
		cfg, err := profile.ClientXray(profile.Profile{Host: "site.test"}, protocol, profile.ClientInbound{SocksPort: socks, BridgePort: b.Port()})
		Must(t, err)
		cli, err := xray.Start(cfg)
		Must(t, err)
		defer cli.Close()
		if got := Get(t, socks, "http://"+target+"/"); got != Hello {
			t.Fatalf("got %q", got)
		}
		old := xray.CheckURL
		xray.CheckURL = "http://" + target + "/big"
		defer func() { xray.CheckURL = old }()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if res, err := cli.Check(ctx, nil); err != nil || res.Bytes != 256<<10 {
			t.Fatalf("check: %+v %v", res, err)
		}
	})

	t.Run("udp-through-bridge", func(t *testing.T) {
		if got := SocksUDP(t, b.Port(), echo, []byte("ping")); string(got) != "ping" {
			t.Fatalf("udp echo got %q", got)
		}
	})
}

// SocksUDP sends one datagram through a SOCKS5 UDP association and returns the reply.
func SocksUDP(t *testing.T, port int, to *net.UDPAddr, payload []byte) []byte {
	t.Helper()
	ctrl, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	Must(t, err)
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))
	ctrl.Write([]byte{5, 1, 0})
	var r [10]byte
	_, err = io.ReadFull(ctrl, r[:2])
	Must(t, err)
	ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	_, err = io.ReadFull(ctrl, r[:])
	Must(t, err)
	if r[1] != 0 {
		t.Fatalf("associate refused: %d", r[1])
	}
	relay := &net.UDPAddr{IP: net.IP(r[4:8]), Port: int(binary.BigEndian.Uint16(r[8:]))}
	uc, err := net.DialUDP("udp", nil, relay)
	Must(t, err)
	defer uc.Close()
	msg := append([]byte{0, 0, 0, 1}, to.IP.To4()...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(to.Port))
	msg = append(msg, payload...)
	buf := make([]byte, 2048)
	for range 20 {
		uc.Write(msg)
		uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := uc.Read(buf); err == nil && n > 10 {
			return buf[10:n]
		}
	}
	t.Fatal("no udp reply")
	return nil
}

// Get fetches url through a SOCKS5 proxy, retrying while the tunnel comes up.
func Get(t *testing.T, socksPort int, url string) string {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	Must(t, err)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.(proxy.ContextDialer).DialContext(ctx, network, addr)
		},
	}}
	var last error
	for range 10 {
		resp, err := c.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b)
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal(last)
	return ""
}

func FreeTCP(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Must(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
