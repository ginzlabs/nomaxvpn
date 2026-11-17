// Package nomaxcore is the tunnel engine for the iOS Network Extension and the
// Android VpnService, bound with gomobile, and for the Windows app, which
// imports it. One Go runtime per process means WireGuard and Xray live in this
// single library.
package nomaxcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/bridged"
	"github.com/ginzlabs/nomaxvpn/internal/l3"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
)

const (
	// Auto tries the protocols in turn and stays on the first that works.
	Auto = "auto"
	// Test tries every protocol, then connects with the quickest.
	Test = "test"
)

// How long Auto and Test give each protocol to prove itself.
const (
	handshakeWait = 3 * time.Second // WireGuard and AmneziaWG
	loginWait     = 8 * time.Second // OpenVPN and OpenConnect: sign-in and one round trip
	checkWait     = 8 * time.Second // everything through Xray: the 256 KB download
	// tlsGap spaces TLS handshakes to the server: some filters block
	// addresses that see several at once.
	tlsGap = time.Second
)

var (
	mu     sync.Mutex
	wg     *device.Device
	pinger *pingTun // wg's OS tunnel
	xr     *xray.Instance
	br     *bridge.Server
	tn     *l3.Tunnel
	active string
	// cancelRun ends the Start in progress; it's guarded by evMu, not mu.
	cancelRun context.CancelFunc
)

// sleep waits for d, or returns false if ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func init() {
	if memoryLimit > 0 {
		debug.SetMemoryLimit(memoryLimit)
		debug.SetGCPercent(50)
	}
}

// Version reports the engine and Xray versions.
func Version() string { return "nomaxcore/2 xray/26.10.31 amneziawg-go" }

// GenerateKey returns a new WireGuard private key, base64.
func GenerateKey() string { return profile.NewWireGuardKey() }

// PublicKey returns the WireGuard public key for a base64 private key.
func PublicKey(privateKey string) (string, error) { return profile.WireGuardPublic(privateKey) }

// ResolveHost returns an IP for host. Call it before applying tunnel network
// settings: once the tunnel's DNS is set, lookups would go into the tunnel.
func ResolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	if len(ips) == 0 {
		return "", errors.New("no address for " + host)
	}
	return ips[0].String(), nil
}

// Endpoint is the server's address for the tunnel to connect to, for the
// app to hand Start (and the OS, as the tunnel's remote address): what the
// profile's host resolves to, else the address the profile lists, else a
// relay's, so a network that blocks the name's lookup still gets a tunnel.
// "" if the profile has none.
func Endpoint(profileJSON string) string {
	var p profile.Profile
	if err := json.Unmarshal([]byte(profileJSON), &p); err != nil {
		return ""
	}
	if ip, err := ResolveHost(p.Host); err == nil {
		return ip
	}
	for _, ip := range p.IPs {
		if net.ParseIP(ip).To4() != nil {
			return ip
		}
	}
	if len(p.IPs) > 0 {
		return p.IPs[0]
	}
	if len(p.Relays) > 0 {
		return p.Relays[0].Address
	}
	return ""
}

// Start runs the tunnel on the packet-tunnel fd and returns the protocol in use.
// protocol is Auto, Test, or one of profile.Protocols. Auto tries them in the
// order it has learned (preferred is what Preferred said last time) and keeps
// the first that passes traffic; Test tries them all and keeps the quickest.
// route is one of the Route constants ("" is Auto). Each step goes to Events.
// tunFd < 0 means find it.
func Start(profileJSON, protocol, route, preferred, wgPrivateKey string, tunFd int32, endpointIP string) (string, error) {
	// A reconnect in progress, or another Start, gives way to this one.
	Cancel()
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	if n := closeStrays(); n > 0 {
		emit(currentRun(), "", stateInfo, "Closed %d tunnel engine(s) left running", n)
	}
	sessionID++
	var p profile.Profile
	if err := json.Unmarshal([]byte(profileJSON), &p); err != nil {
		r := newRun(nil)
		emit(r, "", stateDone, "The saved profile is unreadable: %v", err)
		return "", fmt.Errorf("profile: %w", err)
	}
	hide := secretsOf(p, wgPrivateKey)
	r := newRun(hide)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evMu.Lock()
	cancelRun = cancel
	evMu.Unlock()
	if tunFd < 0 {
		tunFd = int32(findTunFd())
		if tunFd < 0 {
			emit(r, "", stateDone, "The tunnel interface is missing")
			return "", errors.New("tunnel file descriptor not found")
		}
	}
	if route == "" {
		route = RouteAuto
	}
	if route == RouteExit {
		q, ok := p.WithExit()
		if !ok {
			emit(r, "", stateDone, "The server has no exit route")
			return "", errors.New("the server has no exit route")
		}
		p = q
	}
	learnFrom(preferred)
	s := tunnelSession{id: sessionID, p: p, auto: protocol == Auto || protocol == Test, route: route, hide: hide,
		wgKey: wgPrivateKey, fd: int(tunFd), serverIP: endpointIP}
	legs := planLegs(ctx, p, route, Preferred(), endpointIP)
	if len(legs) == 0 {
		emit(r, "", stateDone, "The server has no relay")
		return "", errors.New("the server has no relay")
	}
	if s.auto {
		used, l, err := runAll(ctx, r, s, protocol == Test, legs)
		if err != nil && errors.As(err, new(noneWorked)) {
			if q, ip, ok := moved(ctx, currentRun(), p, s.serverIP); ok {
				s.p, s.serverIP = q, ip
				used, l, err = runAll(ctx, newRun(hide), s, protocol == Test, planLegs(ctx, q, route, Preferred(), ip))
			}
		}
		if err == nil {
			s.endpointIP = l.endpoint
			go watch(s)
		}
		return used, err
	}
	endpointIP = legs[0].endpoint
	if protocol == profile.Cloudflare {
		endpointIP = s.serverIP
	}
	s.endpointIP = endpointIP
	if err := pinServer(endpointIP); err != nil {
		emit(r, "", stateDone, "Couldn't route to the server: %v", err)
		return "", err
	}
	emitOrder(r, protocol, stateStart, []string{protocol}, "Connecting with %s%s", profile.Title(protocol), legs[0].where())
	emit(r, protocol, stateTrying, "Connecting over %s", via(p, protocol))
	if err := startLocked(ctx, r, p, protocol, wgPrivateKey, int(tunFd), endpointIP); err != nil {
		emit(r, protocol, stateFail, "%s", reason(err, 0))
		emit(r, "", stateDone, "%s didn't start", profile.Title(protocol))
		return "", err
	}
	emit(r, protocol, stateTrying, "Started, checking traffic")
	go checkAfterStart(r, protocol, current())
	go watch(s)
	return protocol, nil
}

// checkAfterStart checks a protocol the user picked. It stays on whatever the
// check finds; the log says whether traffic moves.
func checkAfterStart(r int64, protocol string, e engines) {
	ctx, cancel := context.WithTimeout(context.Background(), budget(protocol))
	defer cancel()
	detail, err := check(ctx, r, protocol, e)
	if err != nil {
		emit(r, protocol, stateFail, "Connected, but %s", reason(overdue(ctx, err), budget(protocol)))
		emit(r, "", stateDone, "%s is on, but its traffic check failed", profile.Title(protocol))
		return
	}
	emit(r, protocol, stateOK, "%s", detail)
	emit(r, protocol, stateDone, "Connected with %s", profile.Title(protocol))
}

// runAll is Auto and Test: it tries each leg in turn, each as a run of its
// own, and returns the protocol and the leg that got through. Cancelling ctx
// ends it between steps.
func runAll(ctx context.Context, r int64, s tunnelSession, test bool, legs []leg) (string, leg, error) {
	var err error
	for i, l := range legs {
		if i > 0 {
			r = newRun(s.hide)
		}
		var used string
		used, err = runLeg(ctx, r, s, test, l, i > 0, emitOrder)
		if err == nil {
			return used, l, nil
		}
		if !errors.As(err, new(noneWorked)) {
			return "", l, err
		}
	}
	return "", leg{}, err
}

// runLeg tries one leg's protocols. then says an earlier leg got nothing
// through; start logs the run's start (emitOrder, or the watchdog's
// emitReconnect).
func runLeg(ctx context.Context, r int64, s tunnelSession, test bool, l leg, then bool,
	start func(int64, string, string, []string, string, ...any)) (string, error) {
	order := l.order
	if len(order) == 0 {
		emit(r, "", stateDone, "The profile offers no protocol")
		return "", noneWorked{"The profile offers no protocol"}
	}
	kind := Auto
	if test {
		kind = Test
	}
	if err := pinServer(l.endpoint); err != nil {
		start(r, kind, stateStart, order, "Couldn't route to the server: %v", err)
		emit(r, "", stateDone, "Nothing got through")
		return "", noneWorked{err.Error()}
	}
	over := ""
	if strings.Contains(l.endpoint, ":") {
		over = " over IPv6"
	}
	switch last := lastTitles(order, Preferred()); {
	case test:
		start(r, kind, stateStart, order, "Testing %d protocols%s%s", len(order), l.where(), over)
	case l.blocked && l.relay:
		start(r, kind, stateStart, order, "The relay doesn't answer on TCP. Trying %d protocols through it anyway, %s first", len(order), profile.Title(order[0]))
	case l.blocked:
		start(r, kind, stateStart, order, "The server's address doesn't answer on this network. Trying %d protocols, %s first", len(order), profile.Title(order[0]))
	case then && !l.relay:
		start(r, kind, stateStart, order, "Nothing got through the relay. Trying %d protocols straight to the server%s, %s first", len(order), over, profile.Title(order[0]))
	case then:
		start(r, kind, stateStart, order, "Trying %d protocols through the relay, %s first", len(order), profile.Title(order[0]))
	case len(last) > 0 && len(last) < len(order):
		start(r, kind, stateStart, order, "Trying %d protocols%s%s, %s first and the %d that failed lately last", len(order), l.where(), over, profile.Title(order[0]), len(last))
	default:
		start(r, kind, stateStart, order, "Trying %d protocols%s%s, %s first", len(order), l.where(), over, profile.Title(order[0]))
	}
	used, err := tryAll(ctx, r, s.p, order, test, s.wgKey, s.fd, l.endpoint)
	if errors.As(err, new(noneWorked)) {
		emit(r, "", stateDone, "Nothing got through")
	}
	return used, err
}

// where says, for the log, that a leg goes through the relay.
func (l leg) where() string {
	if l.relay {
		return " through the relay"
	}
	return ""
}

// noneWorked is tryAll's error when no protocol got through: each one's reason.
type noneWorked []string

func (e noneWorked) Error() string { return "No protocol got through.\n" + strings.Join(e, "\n") }

// tryAll tries order in turn and keeps the first protocol that works, or with
// test the quickest. When none works it returns noneWorked and leaves the
// run's done to the caller.
func tryAll(ctx context.Context, r int64, p profile.Profile, order []string, test bool, wgKey string, fd int, endpointIP string) (string, error) {
	began := time.Now()
	var (
		fails    []string
		best     string
		bestTook time.Duration
		lastTLS  time.Time
		worked   = map[string]time.Duration{}
	)
	stopped := func() (string, error) {
		stopLocked()
		emit(r, "", stateDone, "Stopped")
		return "", errors.New("Stopped")
	}
	for _, proto := range order {
		if usesTLS(proto) {
			if !sleep(ctx, time.Until(lastTLS.Add(tlsGap))) {
				return stopped()
			}
			lastTLS = time.Now()
		}
		if ctx.Err() != nil {
			return stopped()
		}
		took, err := attempt(ctx, r, p, proto, wgKey, fd, endpointIP)
		if ctx.Err() != nil {
			return stopped()
		}
		if err != nil {
			learnFailed(proto)
			fails = append(fails, profile.Title(proto)+": "+reason(err, budget(proto)))
			continue
		}
		if !test {
			learnWorked(proto)
			emit(r, proto, stateDone, "Connected with %s after %.1f s", profile.Title(proto), time.Since(began).Seconds())
			return proto, nil
		}
		stopLocked()
		worked[proto] = took
		if best == "" || took < bestTook {
			best, bestTook = proto, took
		}
	}
	learnQuickest(worked)
	if best == "" {
		return "", noneWorked(fails)
	}
	emit(r, "", stateInfo, "Quickest: %s, up in %.1f s. Connecting with it", profile.Title(best), bestTook.Seconds())
	if usesTLS(best) && !sleep(ctx, time.Until(lastTLS.Add(tlsGap))) {
		return stopped()
	}
	if err := startLocked(ctx, r, p, best, wgKey, fd, endpointIP); err != nil {
		emit(r, "", stateDone, "%s worked but didn't start again: %s", profile.Title(best), reason(err, 0))
		return "", err
	}
	emit(r, best, stateDone, "Connected with %s after testing %d protocols", profile.Title(best), len(order))
	return best, nil
}

// attempt starts protocol and checks it within its budget, leaving it running
// if it works and stopped if not. It returns how long it took to work.
func attempt(parent context.Context, r int64, p profile.Profile, protocol, wgKey string, fd int, endpointIP string) (time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, budget(protocol))
	defer cancel()
	emit(r, protocol, stateTrying, "Connecting over %s", via(p, protocol))
	err := startLocked(ctx, r, p, protocol, wgKey, fd, endpointIP)
	if err == nil {
		var detail string
		if detail, err = check(ctx, r, protocol, current()); err == nil {
			emit(r, protocol, stateOK, "%s", detail)
			return time.Since(start), nil
		}
	}
	stopLocked()
	err = overdue(ctx, err)
	emit(r, protocol, stateFail, "%s", reason(err, budget(protocol)))
	return 0, err
}

// overdue is err, or a timeout when err is the connection that ctx's deadline
// closed. Xray flattens errors to text, hence the string match.
func overdue(ctx context.Context, err error) error {
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || err == nil {
		return err
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), io.ErrClosedPipe.Error()) || strings.Contains(err.Error(), net.ErrClosed.Error()) {
		return context.DeadlineExceeded
	}
	return err
}

type kind int

const (
	kindWireGuard kind = iota // amneziawg-go on the fd
	kindXray                  // Xray's tun inbound on the fd
	kindBridge                // Xray's tun inbound into a local SOCKS bridge
	kindL3                    // OpenVPN or OpenConnect on the fd
)

func kindOf(protocol string) kind {
	switch protocol {
	case profile.WireGuard, profile.AmneziaWG:
		return kindWireGuard
	case profile.OpenVPN, profile.OpenConnect:
		return kindL3
	case profile.TrustTunnel, profile.AnyTLS, profile.Mieru:
		return kindBridge
	}
	return kindXray
}

func budget(protocol string) time.Duration {
	switch kindOf(protocol) {
	case kindWireGuard:
		return handshakeWait + pingWait + tunSetup
	case kindL3:
		return loginWait + tunSetup
	}
	return checkWait + tunSetup
}

// usesTLS is true for protocols that open TLS to the server over TCP.
func usesTLS(protocol string) bool {
	switch protocol {
	case profile.Reality, profile.RealityMux, profile.TrustTunnel, profile.AnyTLS, profile.OpenConnect:
		return true
	}
	return false
}

// via says where a protocol connects, for the log.
func via(p profile.Profile, protocol string) string {
	switch protocol {
	case profile.WireGuard:
		return fmt.Sprintf("UDP %d", p.WireGuard.Port)
	case profile.AmneziaWG:
		return fmt.Sprintf("UDP %d", p.AmneziaWG.Port)
	case profile.Hysteria2:
		return fmt.Sprintf("QUIC on UDP %d", p.Hysteria2.Port)
	case profile.Hysteria2Obfs:
		if o := p.Hysteria2.Obfs; o.HopPorts != "" {
			return fmt.Sprintf("UDP %s, changing ports", o.HopPorts)
		}
		return fmt.Sprintf("UDP %d", p.Hysteria2.Obfs.Port)
	case profile.OpenVPN:
		return fmt.Sprintf("UDP %d", p.OpenVPN.Port)
	case profile.OpenConnect:
		return fmt.Sprintf("TLS to %s on TCP %d", p.OpenConnect.Server, p.OpenConnect.Port)
	case profile.Reality:
		return fmt.Sprintf("TLS on TCP %d", p.Reality.Port)
	case profile.RealityMux:
		return fmt.Sprintf("TLS on TCP %d, multiplexed", p.Reality.MuxPort)
	case profile.TrustTunnel:
		return fmt.Sprintf("HTTP/2 to %s on TCP %d", p.Host, p.TrustTunnel.Port)
	case profile.AnyTLS:
		return fmt.Sprintf("padded TLS on TCP %d", p.AnyTLS.Port)
	case profile.Mieru:
		return fmt.Sprintf("TCP %d", p.Mieru.Port)
	case profile.Cloudflare:
		return fmt.Sprintf("WebSocket through Cloudflare to %s", p.Cloudflare.Host)
	}
	return protocol
}

// reason is an error as one short line for the log; budget names a timeout.
func reason(err error, budget time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		if budget > 0 {
			return fmt.Sprintf("no answer within %d s", int(budget.Seconds()))
		}
		return "no answer in time"
	}
	s, _, _ := strings.Cut(err.Error(), "\n")
	return s
}

// secretsOf lists what the log must never show.
func secretsOf(p profile.Profile, wgKey string) []string {
	s := []string{wgKey, p.Reality.UUID}
	if h := p.Hysteria2; h != nil {
		s = append(s, h.Auth)
		if h.Obfs != nil {
			s = append(s, h.Obfs.Password)
		}
	}
	if c := p.OpenConnect; c != nil {
		s = append(s, c.Password)
	}
	if c := p.IKEv2; c != nil {
		s = append(s, c.Password)
	}
	if c := p.TrustTunnel; c != nil {
		s = append(s, c.Password)
	}
	if c := p.AnyTLS; c != nil {
		s = append(s, c.Password)
	}
	if c := p.Mieru; c != nil {
		s = append(s, c.Password)
	}
	if c := p.Cloudflare; c != nil {
		s = append(s, c.Path)
	}
	if e := p.Exit; e != nil {
		s = append(s, e.UUID, e.HysteriaAuth, e.AnyTLSPassword)
	}
	return s
}

// engines is what a check needs, so it can run without holding mu.
type engines struct {
	wg *device.Device
	pt *pingTun
	xr *xray.Instance
	tn *l3.Tunnel
}

func current() engines { return engines{wg, pinger, xr, tn} }

// check proves the running protocol passes traffic and describes how well.
func check(ctx context.Context, r int64, protocol string, e engines) (string, error) {
	start := time.Now()
	switch kindOf(protocol) {
	case kindWireGuard:
		emit(r, protocol, stateTrying, "Waiting for the handshake")
		for handshake(e.wg) == 0 {
			select {
			case <-ctx.Done():
				return "", errors.New("no handshake: the server's replies don't arrive")
			case <-time.After(100 * time.Millisecond):
			}
		}
		shook := fmt.Sprintf("Handshake after %d ms", time.Since(start).Milliseconds())
		if e.pt == nil {
			return shook, nil
		}
		emit(r, protocol, stateTrying, "%s, pinging the server through the tunnel", shook)
		pinged, err := e.pt.pingCheck(ctx, checkPings)
		switch {
		case errors.Is(err, errNoPing):
			return shook, nil
		case err != nil:
			return "", fmt.Errorf("the handshake passed, but %w", err)
		}
		return shook + ", " + pinged, nil
	case kindL3:
		emit(r, protocol, stateTrying, "Signed in as %s, checking the session", e.tn.Address())
		if err := e.tn.Check(ctx); err != nil {
			return "", err
		}
		return fmt.Sprintf("Signed in, address %s", e.tn.Address()), nil
	}
	if e.xr == nil {
		return "", errors.New("not running")
	}
	emit(r, protocol, stateTrying, "Downloading 256 KB through the tunnel")
	res, err := e.xr.Check(ctx, func(step string) { emit(r, protocol, stateTrying, "%s", step) })
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s, first byte after %d ms", speed(res.Speed), res.FirstByte.Milliseconds()), nil
}

func speed(bps float64) string {
	if bps >= 1<<20 {
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	}
	return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
}

func startLocked(ctx context.Context, r int64, p profile.Profile, protocol, wgKey string, fd int, endpointIP string) error {
	if !profile.Offered(p, protocol) {
		return fmt.Errorf("the server doesn't offer %s", profile.Title(protocol))
	}
	switch protocol {
	case profile.WireGuard, profile.AmneziaWG:
		uapi, err := profile.WireGuardUAPI(p, protocol, wgKey, endpointIP)
		if err != nil {
			return err
		}
		t, err := packetTun(fd, p, p.Addresses(protocol))
		if err != nil {
			return err
		}
		pt := newPingTun(t, p.Addresses(protocol), pingTarget(p), tunMTU(p))
		dev := device.NewDevice(pt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
		if err := dev.IpcSet(uapi); err != nil {
			dev.Close()
			return err
		}
		if err := dev.Up(); err != nil {
			dev.Close()
			return err
		}
		wg, pinger = dev, pt
	case profile.Reality, profile.RealityMux, profile.Hysteria2, profile.Hysteria2Obfs, profile.Cloudflare:
		cfg, err := profile.ClientXray(p, protocol, xrayInbound(p, fd, endpointIP))
		if err != nil {
			return err
		}
		inst, err := startXray(cfg)
		if err != nil {
			return err
		}
		xr = inst
	case profile.TrustTunnel, profile.AnyTLS, profile.Mieru:
		// The engine's own sockets skip the tunnel, so it dials the server directly.
		d, err := bridged.Client(p, protocol, endpointIP)
		if err != nil {
			return err
		}
		return startBridged(p, protocol, fd, d)
	case profile.OpenVPN, profile.OpenConnect:
		dev, err := packetTun(fd, p, p.WireGuard.Address)
		if err != nil {
			return err
		}
		if tn, err = l3.Start(ctx, dev, p, protocol, endpointIP); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown protocol %q", protocol)
	}
	if err := feedSystemTun(p, protocol, fd); err != nil {
		stopLocked()
		return err
	}
	active = protocol
	return nil
}

// startBridged runs Xray's tun inbound into a local SOCKS bridge to d, which it owns.
func startBridged(p profile.Profile, protocol string, fd int, d bridge.Dialer) error {
	b, err := bridge.Listen(d)
	if err != nil {
		d.Close()
		return err
	}
	in := xrayInbound(p, fd, "")
	in.BridgePort = b.Port()
	cfg, err := profile.ClientXray(p, protocol, in)
	if err == nil {
		xr, err = startXray(cfg)
	}
	if err != nil {
		b.Close()
		return err
	}
	br = b
	active = protocol
	return nil
}

func tunMTU(p profile.Profile) int {
	if p.WireGuard.MTU > 0 {
		return p.WireGuard.MTU
	}
	return 1280
}

// Cancel ends a Start in progress, Auto and Test included, which then returns
// an error. It doesn't wait for Start's lock, so it works while Start runs.
func Cancel() {
	evMu.Lock()
	c := cancelRun
	evMu.Unlock()
	if c != nil {
		c()
	}
}

// Stop tears the tunnel engine down. Safe to call repeatedly.
func Stop() {
	Cancel()
	mu.Lock()
	defer mu.Unlock()
	sessionID++
	if active != "" {
		emit(currentRun(), "", stateInfo, "Disconnected")
	}
	stopLocked()
	if n := closeStrays(); n > 0 {
		emit(currentRun(), "", stateInfo, "Closed %d tunnel engine(s) left running", n)
	}
	if clearTun() {
		emit(currentRun(), "", stateInfo, "Took down routes and DNS the tunnel left behind")
	}
	unpinServer()
	newRun(nil)
}

func stopLocked() {
	if wg != nil {
		wg.Close()
		wg, pinger = nil, nil
	}
	if xr != nil {
		closeXray(xr)
		xr = nil
	}
	if br != nil {
		closeSoon(br)
		br = nil
	}
	if tn != nil {
		tn.Close()
		tn = nil
	}
	active = ""
	debug.FreeOSMemory()
}

// closeSoon closes c but waits for it only briefly: a bridge's client can be
// stuck on a blocked server, and the next protocol, or Disconnect, shouldn't
// wait for that. The bridge holds no system resources besides loopback.
func closeSoon(c io.Closer) {
	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// BumpSockets rebinds WireGuard's UDP sockets after a network change (Wi-Fi to
// cellular), and reconnects OpenVPN and OpenConnect.
func BumpSockets() {
	mu.Lock()
	defer mu.Unlock()
	if wg != nil {
		wg.BindUpdate()
	}
	if tn != nil {
		tn.Bump()
	}
}

// Handshake is the Unix time of the last WireGuard handshake, 0 if none.
func Handshake() int64 {
	mu.Lock()
	defer mu.Unlock()
	return handshake(wg)
}

func handshake(dev *device.Device) int64 {
	if dev == nil {
		return 0
	}
	v, _ := wgStat(dev, "last_handshake_time_sec")
	return v
}

func wgStat(dev *device.Device, key string) (int64, error) {
	s, err := dev.IpcGet()
	if err != nil {
		return 0, err
	}
	var total int64
	for line := range strings.SplitSeq(s, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			total += n
		}
	}
	return total, nil
}

// Stats returns {"protocol","rx","tx","handshake"} as JSON for the app's status view.
func Stats() string {
	mu.Lock()
	defer mu.Unlock()
	rx, tx := trafficLocked()
	b, _ := json.Marshal(map[string]any{"protocol": active, "rx": rx, "tx": tx, "handshake": handshake(wg)})
	return string(b)
}

// trafficLocked is the bytes the running engine has received and sent.
func trafficLocked() (rx, tx int64) {
	switch {
	case wg != nil:
		rx, _ = wgStat(wg, "rx_bytes")
		tx, _ = wgStat(wg, "tx_bytes")
	case xr != nil:
		rx = xr.Counter("outbound>>>proxy>>>traffic>>>downlink")
		tx = xr.Counter("outbound>>>proxy>>>traffic>>>uplink")
	case tn != nil:
		rx, tx = tn.Traffic()
	}
	return rx, tx
}
