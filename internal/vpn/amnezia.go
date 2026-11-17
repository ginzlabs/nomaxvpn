package vpn

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// AmneziaWG runs in-process on its own TUN interface. Devices keep their
// WireGuard addresses; replies leave through the interface their connection
// came in on (nftables marks awg0 connections, table 52 routes them back).
const (
	AWGInterface = "awg0"
	AWGPort      = 51821
	awgMark      = "0x2"
	awgTable     = "52"
)

type amnezia struct {
	dev   *device.Device
	peers map[string]bool // hex public keys currently configured
}

func startAmnezia(privateKey string, obfs profile.AmneziaObfs) (*amnezia, error) {
	priv, err := keyToHex(privateKey)
	if err != nil {
		return nil, err
	}
	t, err := tun.CreateTUN(AWGInterface, MTU)
	if err != nil {
		return nil, fmt.Errorf("amneziawg: tun: %w", err)
	}
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "amneziawg: "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", priv, AWGPort) + obfs.UAPI()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("amneziawg: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("amneziawg: %w", err)
	}
	for _, args := range [][]string{
		{"link", "set", AWGInterface, "up"},
		{"route", "replace", "10.8.0.0/24", "dev", AWGInterface, "table", awgTable},
		{"-6", "route", "replace", "fd08::/64", "dev", AWGInterface, "table", awgTable},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("amneziawg: ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	for _, fam := range []string{"-4", "-6"} {
		exec.Command("ip", fam, "rule", "del", "priority", "100").Run()
		if out, err := exec.Command("ip", fam, "rule", "add", "priority", "100", "fwmark", awgMark, "lookup", awgTable).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("amneziawg: ip rule: %v: %s", err, out)
		}
	}
	return &amnezia{dev: dev, peers: map[string]bool{}}, nil
}

// setPeers adds or updates every device and removes the rest, leaving live sessions alone.
func (a *amnezia) setPeers(devices []store.Device) error {
	var b strings.Builder
	want := map[string]bool{}
	for _, d := range devices {
		k, err := keyToHex(d.WGPublicKey)
		if err != nil {
			continue
		}
		want[k] = true
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\nallowed_ip=%s/128\n", k, d.IPv4(), d.IPv6())
	}
	for k := range a.peers {
		if !want[k] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if err := a.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("amneziawg: peers: %w", err)
	}
	a.peers = want
	return nil
}

type peerStat struct {
	rx, tx    int64
	handshake int64
}

// stats returns per-peer counters keyed by base64 public key.
func (a *amnezia) stats() map[string]peerStat {
	out := map[string]peerStat{}
	s, err := a.dev.IpcGet()
	if err != nil {
		return out
	}
	var cur string
	var st peerStat
	flush := func() {
		if cur != "" {
			out[cur] = st
		}
	}
	for line := range strings.SplitSeq(s, "\n") {
		k, v, _ := strings.Cut(line, "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "public_key":
			flush()
			raw, _ := hex.DecodeString(v)
			cur, st = base64.StdEncoding.EncodeToString(raw), peerStat{}
		case "rx_bytes":
			st.rx = n
		case "tx_bytes":
			st.tx = n
		case "last_handshake_time_sec":
			st.handshake = n
		}
	}
	flush()
	return out
}

func (a *amnezia) close() { a.dev.Close() }

func keyToHex(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("bad key")
	}
	return hex.EncodeToString(k), nil
}
