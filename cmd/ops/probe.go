package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/bridged"
	"github.com/ginzlabs/nomaxvpn/internal/l3"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
)

type contextT = context.Context

// cmdProbe enrols a throwaway device with the review code, checks that every
// protocol carries traffic out of the server's IP, then removes the device.
func cmdProbe(env *Env, _ []string) {
	domain := env.Must("DOMAIN")
	host := serverHost(env)
	serverIP := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			fatalf("resolve %s: %v", host, err)
		}
		serverIP = ips[0]
	}
	client := httpClientTo(domain, serverIP, false)

	wgKey := profile.NewWireGuardKey()
	wgPub, _ := profile.WireGuardPublic(wgKey)
	body, _ := json.Marshal(map[string]string{"pin": env.Must("REVIEW_CODE"), "deviceName": "ops probe", "wgPublicKey": wgPub})
	resp, err := client.Post("https://"+domain+profile.APIBase(env.Get("API_PATH"))+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		fatalf("enroll: %v", err)
	}
	var en struct {
		DeviceToken string          `json:"deviceToken"`
		Profile     profile.Profile `json:"profile"`
		Error       string          `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&en)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		fatalf("enroll: %d %s", resp.StatusCode, en.Error)
	}
	step("enrolled probe device")
	remove := func() {
		req, _ := http.NewRequest("DELETE", "https://"+domain+profile.APIBase(env.Get("API_PATH"))+"/device", nil)
		req.Header.Set("Authorization", "Bearer "+en.DeviceToken)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			step("removed probe device (%d)", resp.StatusCode)
		}
	}
	// The probe device exists only here, so the new server wouldn't let it in.
	if en.Profile.Host != domain {
		step("profiles send apps to %s (MOVED_TO); probe that server with its own config", en.Profile.Host)
		remove()
		return
	}
	time.Sleep(2 * time.Second)

	failed := false
	// route connects every protocol p offers to endpoint and checks traffic
	// leaves from want. Through a relay Cloudflare is left out, as it never
	// goes that way; with the exit, the protocols Xray doesn't carry are.
	route := func(title string, p profile.Profile, endpoint, want string, relayed, exit bool) {
		step("%s", title)
		report := func(proto string, ip string, d time.Duration, err error) {
			switch {
			case err != nil:
				failed = true
				fmt.Printf("  %-13s FAIL  %v\n", proto, err)
			case ip != want:
				failed = true
				fmt.Printf("  %-13s FAIL  exit IP %s, want %s\n", proto, ip, want)
			default:
				fmt.Printf("  %-13s ok    exit %s in %s\n", proto, ip, d.Round(time.Millisecond))
			}
		}
		missing := func(proto string) {
			failed = true
			fmt.Printf("  %-13s FAIL  server offers no %s\n", proto, proto)
		}

		needsCert := map[string]bool{profile.Hysteria2: true, profile.Hysteria2Obfs: true, profile.TrustTunnel: true, profile.AnyTLS: true}
		for _, proto := range []string{profile.Reality, profile.RealityMux, profile.Hysteria2, profile.Hysteria2Obfs, profile.TrustTunnel, profile.AnyTLS, profile.Mieru, profile.Cloudflare} {
			if proto == profile.Cloudflare && relayed {
				continue
			}
			if !profile.Offered(p, proto) {
				if needsCert[proto] && p.Hysteria2 == nil {
					fmt.Printf("  %-13s skip  server has no certificate yet\n", proto)
				} else {
					missing(proto)
				}
				continue
			}
			start := time.Now()
			ip, err := probeXray(p, proto, endpoint)
			report(proto, ip, time.Since(start), err)
		}
		if exit {
			return
		}
		for _, proto := range []string{profile.WireGuard, profile.AmneziaWG} {
			if proto == profile.AmneziaWG && p.AmneziaWG == nil {
				missing(proto)
				continue
			}
			start := time.Now()
			ip, err := probeWireGuard(p, proto, wgKey, endpoint)
			report(proto, ip, time.Since(start), err)
		}
		for _, proto := range []string{profile.OpenVPN, profile.OpenConnect} {
			if (proto == profile.OpenVPN && p.OpenVPN == nil) || (proto == profile.OpenConnect && p.OpenConnect == nil) {
				missing(proto)
				continue
			}
			start := time.Now()
			ip, err := probeL3(p, proto, endpoint)
			report(proto, ip, time.Since(start), err)
		}
		switch _, err := exec.LookPath("swanctl"); {
		case p.IKEv2 == nil:
			missing(profile.IKEv2)
		case runtime.GOOS != "linux" || err != nil:
			fmt.Printf("  %-13s skip  needs Linux with strongSwan (CI runs it)\n", profile.IKEv2)
		default:
			c := *p.IKEv2
			if relayed {
				c.Server = endpoint
			}
			start := time.Now()
			ip, err := probeIKEv2(c)
			report(profile.IKEv2, ip, time.Since(start), err)
		}
	}

	route("straight to the server", en.Profile, serverIP, serverIP, false, false)
	for _, r := range en.Profile.Relays {
		route("through the relay at "+r.Address, en.Profile, r.Address, serverIP, true, false)
	}
	if ex, ok := en.Profile.WithExit(); ok && len(en.Profile.Relays) > 0 {
		route("Exit route, leaving from "+en.Profile.Relays[0].Address, ex, serverIP, en.Profile.Relays[0].Address, false, true)
	}
	remove()
	if failed {
		fatalf("probe failed")
	}
}

// probeXray runs a protocol Xray carries the way the apps do, TrustTunnel,
// AnyTLS and Mieru through the bridge, and pulls 256 KB through it as well,
// since a filter can let a connection start and then freeze it.
func probeXray(p profile.Profile, proto, serverIP string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	in := profile.ClientInbound{SocksPort: port, Address: serverIP}
	if proto == profile.TrustTunnel || proto == profile.AnyTLS || proto == profile.Mieru {
		d, err := bridged.Client(p, proto, serverIP)
		if err != nil {
			return "", err
		}
		// Through Xray a failed dial is only an EOF; going direct first shows why.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = traceIP(ctx, func(ctx context.Context) (net.Conn, error) { return d.DialTCP(ctx, "1.1.1.1:443") })
		cancel()
		if err != nil {
			d.Close()
			return "", fmt.Errorf("direct: %w", err)
		}
		b, err := bridge.Listen(d)
		if err != nil {
			d.Close()
			return "", err
		}
		defer b.Close()
		in.BridgePort = b.Port()
	}
	cfg, err := profile.ClientXray(p, proto, in)
	if err != nil {
		return "", err
	}
	inst, err := xray.Start(cfg)
	if err != nil {
		return "", err
	}
	defer inst.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ip, err := traceIP(ctx, func(ctx context.Context) (net.Conn, error) { return inst.Dial(ctx, "1.1.1.1:443") })
	if err != nil {
		return "", err
	}
	if _, err := inst.Check(ctx, nil); err != nil {
		return ip, fmt.Errorf("256 KB check: %w", err)
	}
	return ip, nil
}

func probeWireGuard(p profile.Profile, proto, key, serverIP string) (string, error) {
	var addrs []netip.Addr
	for _, a := range p.Addresses(proto) {
		pfx, err := netip.ParsePrefix(a)
		if err == nil {
			addrs = append(addrs, pfx.Addr())
		}
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, p.WireGuard.MTU)
	if err != nil {
		return "", err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	uapi, err := profile.WireGuardUAPI(p, proto, key, serverIP)
	if err != nil {
		return "", err
	}
	if err := dev.IpcSet(uapi); err != nil {
		return "", err
	}
	if err := dev.Up(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ip, err := traceAndCheck(ctx, tnet)
	if err != nil {
		return ip, err
	}
	return ip, pingServer(tnet, p)
}

// pingServer pings the server's IPv4 from inside the tunnel, which the apps'
// check relies on.
func pingServer(tnet *netstack.Net, p profile.Profile) error {
	var dst netip.Addr
	for _, s := range p.IPs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			dst = a
			break
		}
	}
	if !dst.IsValid() {
		return errors.New("ping: the profile lists no IPv4")
	}
	pc, err := tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return err
	}
	defer pc.Close()
	reply := make([]byte, 2048)
	for seq := range 3 {
		echo := make([]byte, 8+1200)
		echo[0], echo[7] = 8, byte(seq)
		if _, err := pc.Write(echo); err != nil {
			return fmt.Errorf("ping: %w", err)
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := pc.Read(reply); err == nil && n >= 8 && reply[0] == 0 {
			return nil
		}
	}
	return errors.New("the server doesn't answer pings through the tunnel")
}

// traceAndCheck asks for the exit address through a userspace tunnel, then
// pulls the apps' 256 KB check through it, since some filters let a
// tunnel's first few KB through and then stop it.
func traceAndCheck(ctx context.Context, tnet *netstack.Net) (string, error) {
	dial := func(ctx context.Context, addr string) (net.Conn, error) { return tnet.DialContext(ctx, "tcp", addr) }
	ip, err := traceIP(ctx, func(ctx context.Context) (net.Conn, error) { return dial(ctx, "1.1.1.1:443") })
	if err != nil {
		return "", err
	}
	if _, err := xray.Fetch(ctx, dial, xray.CheckURL, nil); err != nil {
		return ip, fmt.Errorf("256 KB check: %w", err)
	}
	return ip, nil
}

// probeL3 runs OpenVPN or OpenConnect the way the apps do: the core's client
// over a userspace TUN with the device's WireGuard addresses.
func probeL3(p profile.Profile, proto, serverIP string) (string, error) {
	var addrs []netip.Addr
	for _, a := range p.WireGuard.Address {
		if pfx, err := netip.ParsePrefix(a); err == nil {
			addrs = append(addrs, pfx.Addr())
		}
	}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, p.WireGuard.MTU)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t, err := l3.Start(ctx, tunDev, p, proto, serverIP)
	if err != nil {
		return "", err
	}
	defer t.Close()
	return traceAndCheck(ctx, tnet)
}

// probeIKEv2 brings up a strongSwan client (via sudo) that sends only 1.0.0.1
// through the tunnel. It trusts just the ISRG roots, so the server must send
// its intermediates the way iOS needs them. Files go under /etc/swanctl because
// Ubuntu's AppArmor profile keeps swanctl out of everywhere else.
func probeIKEv2(c profile.IKEv2Conf) (string, error) {
	const confPath = "/etc/swanctl/conf.d/nomax-probe.conf"
	var log strings.Builder
	run := func(stdin string, args ...string) error {
		cmd := exec.Command("sudo", args...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		for line := range strings.SplitSeq(string(out), "\n") {
			if !strings.HasPrefix(line, "plugin '") && strings.TrimSpace(line) != "" {
				fmt.Fprintf(&log, "    %s\n", line)
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %v\n%s", strings.Join(args[:2], " "), err, log.String())
		}
		return nil
	}
	conf := fmt.Sprintf(`connections {
	nomax-probe {
		version = 2
		remote_addrs = %s
		vips = 0.0.0.0
		local {
			auth = eap-mschapv2
			id = %s
		}
		remote {
			auth = pubkey
			id = %s
			cacerts = nomax-probe-x1.pem, nomax-probe-x2.pem
		}
		children {
			nomax-probe {
				remote_ts = 1.0.0.1/32
			}
		}
	}
}
secrets {
	eap-probe {
		id = %s
		secret = "%s"
	}
}
`, c.Server, c.Username, c.RemoteID, c.Username, c.Password)
	for _, step := range [][]string{
		{"install", "-m", "644", "/etc/ssl/certs/ISRG_Root_X1.pem", "/etc/swanctl/x509ca/nomax-probe-x1.pem"},
		{"install", "-m", "644", "/etc/ssl/certs/ISRG_Root_X2.pem", "/etc/swanctl/x509ca/nomax-probe-x2.pem"},
		{"sh", "-c", "umask 077; cat > " + confPath},
	} {
		if err := run(conf, step...); err != nil {
			return "", err
		}
	}
	log.Reset()
	defer func() {
		run("", "swanctl", "--terminate", "--ike", "nomax-probe", "--timeout", "5")
		run("", "rm", "-f", confPath, "/etc/swanctl/x509ca/nomax-probe-x1.pem", "/etc/swanctl/x509ca/nomax-probe-x2.pem")
		run("", "swanctl", "--load-all", "--noprompt")
	}()
	if err := run("", "swanctl", "--load-all", "--noprompt"); err != nil {
		return "", err
	}
	if err := run("", "swanctl", "--initiate", "--child", "nomax-probe", "--timeout", "20"); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	return traceIP(ctx, func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", "1.0.0.1:443") })
}

// traceIP asks Cloudflare which address the request came from.
func traceIP(ctx context.Context, dial func(context.Context) (net.Conn, error)) (string, error) {
	var last error
	for ctx.Err() == nil {
		if last != nil {
			fmt.Printf("    retrying after: %v\n", last)
		}
		c, err := dial(ctx)
		if err != nil {
			last = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		dl, _ := ctx.Deadline()
		c.SetDeadline(dl)
		tc := tls.Client(c, &tls.Config{ServerName: "one.one.one.one"})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			last = err
			continue
		}
		c = tc
		io.WriteString(c, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			c.Close()
			last = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		c.Close()
		for line := range strings.SplitSeq(string(b), "\n") {
			if ip, ok := strings.CutPrefix(line, "ip="); ok {
				return strings.TrimSpace(ip), nil
			}
		}
		return "", fmt.Errorf("no ip in trace (status %d)", resp.StatusCode)
	}
	if last == nil {
		last = ctx.Err()
	}
	return "", last
}
