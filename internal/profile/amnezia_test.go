package profile_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
)

func TestAmneziaParams(t *testing.T) {
	a, b := profile.AmneziaParams("secret"), profile.AmneziaParams("secret")
	if a != b {
		t.Fatal("params must be stable")
	}
	if a == profile.AmneziaParams("other") {
		t.Fatal("params should depend on the secret")
	}
	hs := map[uint32]bool{a.H1: true, a.H2: true, a.H3: true, a.H4: true}
	if len(hs) != 4 || hs[1] || hs[2] || hs[3] || hs[4] {
		t.Fatalf("headers must be distinct and not WireGuard's: %+v", a)
	}
	if a.Jc < 1 || a.Jmin >= a.Jmax || a.Jmax > 1280 || a.S1+56 == a.S2 {
		t.Fatalf("invalid params %+v", a)
	}
}

// TestAmneziaLoopback runs an AmneziaWG server and client on userspace network
// stacks and fetches a page through the tunnel; a plain WireGuard client must not get in.
func TestAmneziaLoopback(t *testing.T) {
	serverKey, clientKey := profile.NewWireGuardKey(), profile.NewWireGuardKey()
	serverPub, _ := profile.WireGuardPublic(serverKey)
	clientPub, _ := profile.WireGuardPublic(clientKey)
	obfs := profile.AmneziaParams(serverKey)

	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(srv.Close)
	port := freeUDPPort(t)
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n%spublic_key=%s\nallowed_ip=10.8.0.2/32\n",
		hexKey(t, serverKey), port, obfs.UAPI(), hexKey(t, clientPub))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := snet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello via amneziawg") }))

	p := profile.Profile{
		WireGuard: profile.WireGuardConf{Port: port, ServerPublicKey: serverPub, Address: []string{"10.8.0.2/32"}, MTU: 1280},
		AmneziaWG: &profile.AmneziaConf{Port: port, Address: []string{"10.8.0.2/32"}, AmneziaObfs: obfs},
	}
	if body, err := fetchVia(t, p, profile.AmneziaWG, clientKey, 10*time.Second); err != nil || body != "hello via amneziawg" {
		t.Fatalf("amneziawg: %q %v", body, err)
	}
	if body, err := fetchVia(t, p, profile.WireGuard, clientKey, 3*time.Second); err == nil {
		t.Fatalf("plain WireGuard got through an AmneziaWG server: %q", body)
	}
}

// TestWireGuardThroughXray is WireGuard as the Windows app runs it: Xray's own
// client against a plain WireGuard server.
func TestWireGuardThroughXray(t *testing.T) {
	serverKey, clientKey := profile.NewWireGuardKey(), profile.NewWireGuardKey()
	serverPub, _ := profile.WireGuardPublic(serverKey)
	clientPub, _ := profile.WireGuardPublic(clientKey)

	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(srv.Close)
	port := freeUDPPort(t)
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.8.0.2/32\n",
		hexKey(t, serverKey), port, hexKey(t, clientPub))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := snet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello via xray wireguard") }))

	p := profile.Profile{
		Host:      host,
		WireGuard: profile.WireGuardConf{Port: port, ServerPublicKey: serverPub, Address: []string{"10.8.0.2/32"}, MTU: 1280},
	}
	socks := freeTCP(t)
	cfg, err := profile.ClientXray(p, profile.WireGuard, profile.ClientInbound{SocksPort: socks, Address: "127.0.0.1", WireGuardKey: clientKey})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := xray.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if got := getVia(t, socks, "http://10.8.0.1/"); got != "hello via xray wireguard" {
		t.Fatalf("got %q", got)
	}
}

func fetchVia(t *testing.T, p profile.Profile, proto, key string, timeout time.Duration) (string, error) {
	ctun, cnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cli := device.NewDevice(ctun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer cli.Close()
	uapi, err := profile.WireGuardUAPI(p, proto, key, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{DialContext: cnet.DialContext}}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://10.8.0.1/", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func hexKey(t *testing.T, b64 string) string {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k)
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
