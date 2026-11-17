// Package vpn keeps Xray, WireGuard, AmneziaWG and strongSwan in line with the
// device list, and collects per-device traffic.
package vpn

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/mieru"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"github.com/ginzlabs/nomaxvpn/internal/trusttunnel"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	WGInterface = "wg0"
	WGPort      = 51820
	MTU         = 1280

	RealityMuxPort = 2053
	// ObfsPort is Hysteria2 Obfs; nftables redirects HopPorts to it.
	ObfsPort   = 8443
	HopPorts   = "20000-20999"
	AnyTLSPort = 2083
	MieruPort  = 2096
)

type Config struct {
	Server       profile.Server
	WGPrivateKey string
	// StateDir keeps the OpenVPN CA; RunDir its management socket. Empty means no OpenVPN.
	StateDir, RunDir string
	// AnyTLSPort and MieruPort run those protocols; 0 means off.
	AnyTLSPort, MieruPort int
	// Relays are the relays' IPv4 addresses (RELAYS); the first carries the
	// exit over the link (infra/host/setup.sh, cmd/ops/relay.go).
	Relays []string
	// MovedTo (MOVED_TO) is the server's new name: profiles send apps there,
	// while this server keeps Server.Host for its own certificates and logins.
	MovedTo string
}

// ExitLink is the server's end of the relay link: connections from it go
// to the first relay and out from there.
const ExitLink = "10.9.0.1"

// exitEmail is the device's exit login.
func exitEmail(d store.Device) string { return d.Email() + "x" }

type Runtime struct {
	cfg        Config
	wgPub      string
	realityPub string
	obfs       profile.AmneziaObfs
	ikeKey     []byte
	log        *slog.Logger

	mu      sync.Mutex
	inst    *xray.Instance
	applied []byte
	cert    struct{ cert, key string }
	ikeCert struct{ cert, key string } // for IKEServer(Host), when that's another name
	ocCert  struct{ cert, key string } // for OCServer(Host)
	awg     *amnezia
	ike     *ikev2
	ovpn    *openvpn
	oc      *openconnect
	wgSeen  map[string]wgCounters
	awgSeen map[string]wgCounters
	// logins are the devices' TrustTunnel passwords, by username.
	logins map[string]string
	anytls *anyTLSServer
	mieru  *mieru.Server
	// site is the website, for AnyTLS connections without a login.
	site http.Handler

	cfMu  sync.Mutex
	cfIPs []string
	cfAt  time.Time

	// ips are the server's public addresses.
	ips []string
}

// publicIPs are the interfaces' global addresses, which are the server's own
// on a host with no NAT in front of it.
func publicIPs() []string {
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if ok && n.IP.IsGlobalUnicast() && !n.IP.IsPrivate() {
			out = append(out, n.IP.String())
		}
	}
	return out
}

type wgCounters struct{ rx, tx int64 }

func New(cfg Config, log *slog.Logger) (*Runtime, error) {
	pub, err := profile.WireGuardPublic(cfg.WGPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("vpn: wireguard key: %w", err)
	}
	rpub, err := profile.RealityPublic(cfg.Server.RealityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("vpn: reality key: %w", err)
	}
	ikeKey := sha256.Sum256([]byte("nomax ikev2\x00" + cfg.WGPrivateKey))
	if cfg.Server.ObfsPort != 0 && cfg.Server.ObfsPassword == "" {
		// Salamander has one password per listener, so every device shares it.
		sum := sha256.Sum256([]byte("nomax salamander\x00" + cfg.WGPrivateKey))
		cfg.Server.ObfsPassword = base64.RawURLEncoding.EncodeToString(sum[:])[:24]
	}
	if cfg.Server.CloudflareAddr != "" && cfg.Server.CloudflarePath == "" {
		// Unguessable, so the website shows nothing there to a scan.
		sum := sha256.Sum256([]byte("nomax cloudflare\x00" + cfg.WGPrivateKey))
		cfg.Server.CloudflarePath = "/" + base64.RawURLEncoding.EncodeToString(sum[:])[:20]
	}
	if len(cfg.Relays) > 0 && cfg.Server.ExitVia == "" {
		cfg.Server.ExitVia = ExitLink
	}
	return &Runtime{
		cfg: cfg, wgPub: pub, realityPub: rpub, obfs: profile.AmneziaParams(cfg.WGPrivateKey), ikeKey: ikeKey[:], log: log,
		wgSeen: map[string]wgCounters{}, awgSeen: map[string]wgCounters{}, ips: publicIPs(),
	}, nil
}

// exit reports whether devices get an exit login.
func (r *Runtime) exit() bool { return r.cfg.Server.ExitVia != "" }

// exitUUID is the device's Reality and Cloudflare UUID for the exit,
// derived like its passwords.
func (r *Runtime) exitUUID(d store.Device) string {
	m := hmac.New(sha256.New, r.ikeKey)
	m.Write([]byte("exit uuid\x00" + d.UUID))
	b := m.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// SetCert installs the TLS certificate Hysteria2 and IKEv2 use. Call Apply afterwards.
func (r *Runtime) SetCert(certPEM, keyPEM string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cert.cert, r.cert.key = certPEM, keyPEM
}

// SetIKECert installs the certificate for the IPv4-only name IKEv2 clients dial
// (IKEServer). Android expects the server to identify as the name it dialed. Call Apply afterwards.
func (r *Runtime) SetIKECert(certPEM, keyPEM string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ikeCert.cert, r.ikeCert.key = certPEM, keyPEM
}

// SetOCCert installs the certificate for OCServer(Host). Call Apply afterwards.
func (r *Runtime) SetOCCert(certPEM, keyPEM string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ocCert.cert, r.ocCert.key = certPEM, keyPEM
}

func (r *Runtime) HasHysteria() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert.cert != ""
}

// Apply rebuilds Xray (only when its config changed) and reconciles the peers
// and secrets of the other protocols.
func (r *Runtime) Apply(devices []store.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	srv := r.cfg.Server
	srv.CertPEM, srv.KeyPEM = r.cert.cert, r.cert.key
	xd := make([]profile.Device, 0, len(devices))
	for _, d := range devices {
		xd = append(xd, profile.Device{Email: d.Email(), UUID: d.UUID, HysteriaAuth: d.HysteriaAuth})
	}
	if r.exit() {
		for _, d := range devices {
			xd = append(xd, profile.Device{Email: exitEmail(d), UUID: r.exitUUID(d), HysteriaAuth: r.secret(d, "exit hysteria2")})
			srv.ExitEmails = append(srv.ExitEmails, exitEmail(d))
		}
	}
	cfg, err := profile.ServerXray(srv, xd)
	if err != nil {
		return err
	}
	r.logins = make(map[string]string, len(devices))
	for _, d := range devices {
		r.logins[d.Email()] = r.secret(d, profile.TrustTunnel)
		if r.exit() {
			r.logins[exitEmail(d)] = r.secret(d, profile.TrustTunnel)
		}
	}
	var errs []error
	if !bytes.Equal(cfg, r.applied) {
		if r.inst != nil {
			r.inst.Close()
			r.inst = nil
		}
		inst, err := xray.Start(cfg)
		if err != nil {
			r.applied = nil
			errs = append(errs, err)
		} else {
			r.inst, r.applied = inst, cfg
			r.log.Info("xray applied", "devices", len(devices), "hysteria2", srv.CertPEM != "")
		}
	}
	if err := r.applyWireGuard(devices); err != nil {
		errs = append(errs, err)
	}
	if r.awg == nil {
		a, err := startAmnezia(r.cfg.WGPrivateKey, r.obfs)
		if err != nil {
			errs = append(errs, err)
		} else {
			r.awg = a
			r.log.Info("amneziawg up", "port", AWGPort)
		}
	}
	if r.awg != nil {
		if err := r.awg.setPeers(devices); err != nil {
			errs = append(errs, err)
		}
	}
	if err := r.applyIKEv2(devices); err != nil {
		errs = append(errs, err)
	}
	if r.ovpn == nil && r.cfg.StateDir != "" && r.cfg.RunDir != "" {
		o, err := startOpenVPN(filepath.Join(r.cfg.StateDir, "openvpn"), r.cfg.RunDir, r.cfg.Server.Host, r.log)
		if err != nil {
			errs = append(errs, err)
		} else {
			r.ovpn = o
		}
	}
	if r.ovpn != nil {
		if err := r.ovpn.setClients(devices); err != nil {
			errs = append(errs, fmt.Errorf("openvpn: %w", err))
		}
	}
	if r.oc == nil && r.cfg.StateDir != "" && OCServer(r.cfg.Server.Host) != "" {
		o, err := startOpenConnect(filepath.Join(r.cfg.StateDir, "ocserv"))
		if err != nil {
			errs = append(errs, fmt.Errorf("ocserv: %w", err))
		}
		r.oc = o
	}
	if r.oc != nil {
		if err := r.oc.setUsers(devices, r.ikePassword, r.ocSalt); err != nil {
			errs = append(errs, err)
		}
		if r.ocCert.cert != "" {
			if err := r.oc.setCert(r.ocCert.cert, r.ocCert.key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if r.anytls == nil && r.cfg.AnyTLSPort != 0 && r.cert.cert != "" {
		a, err := r.startAnyTLS()
		if err != nil {
			errs = append(errs, fmt.Errorf("anytls: %w", err))
		} else {
			r.anytls = a
			r.log.Info("anytls up", "port", r.cfg.AnyTLSPort)
		}
	}
	if r.anytls != nil {
		if err := r.anytls.setCert(r.cert.cert, r.cert.key); err != nil {
			errs = append(errs, fmt.Errorf("anytls: %w", err))
		}
		users := make(map[string]string, len(devices))
		for _, d := range devices {
			users[r.secret(d, profile.AnyTLS)] = d.Email()
			if r.exit() {
				users[r.secret(d, "exit anytls")] = exitEmail(d)
			}
		}
		if err := r.anytls.setUsers(users); err != nil {
			errs = append(errs, fmt.Errorf("anytls: %w", err))
		}
	}
	if r.cfg.MieruPort != 0 {
		if r.mieru == nil {
			r.mieru = &mieru.Server{IP: r.cfg.Server.Listen, Port: r.cfg.MieruPort, DialTCP: r.dialTCP(profile.Mieru), DialUDP: r.dialUDP(profile.Mieru)}
		}
		users := make(map[string]string, len(devices))
		for _, d := range devices {
			users[d.Email()] = r.secret(d, profile.Mieru)
			if r.exit() {
				users[exitEmail(d)] = r.secret(d, profile.Mieru)
			}
		}
		if err := r.mieru.SetUsers(users); err != nil {
			errs = append(errs, fmt.Errorf("mieru: %w", err))
		}
	}
	return errors.Join(errs...)
}

// applyWireGuard adds or updates every device and removes the rest. It never
// replaces the whole peer list, which would drop every live session.
func (r *Runtime) applyWireGuard(devices []store.Device) error {
	wc, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	defer wc.Close()
	cur, err := wc.Device(WGInterface)
	if err != nil {
		return fmt.Errorf("wireguard: %s: %w", WGInterface, err)
	}
	key, _ := wgtypes.ParseKey(r.cfg.WGPrivateKey)
	port := WGPort
	peers := make([]wgtypes.PeerConfig, 0, len(devices))
	want := map[wgtypes.Key]bool{}
	for _, d := range devices {
		pk, err := wgtypes.ParseKey(d.WGPublicKey)
		if err != nil {
			continue
		}
		want[pk] = true
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         pk,
			ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{
				{IP: net.ParseIP(d.IPv4()), Mask: net.CIDRMask(32, 32)},
				{IP: net.ParseIP(d.IPv6()), Mask: net.CIDRMask(128, 128)},
			},
		})
	}
	for _, p := range cur.Peers {
		if !want[p.PublicKey] {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	cfg := wgtypes.Config{Peers: peers}
	if cur.PrivateKey != key || cur.ListenPort != port {
		cfg.PrivateKey, cfg.ListenPort = &key, &port
	}
	return wc.ConfigureDevice(WGInterface, cfg)
}

// TakeUsage returns traffic since the last call, keyed by device id.
func (r *Runtime) TakeUsage(devices []store.Device) map[int64]store.Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[int64]store.Usage{}
	byEmail := map[string]int64{}
	byKey := map[string]int64{}
	byUUID := map[string]int64{}
	for _, d := range devices {
		byEmail[d.Email()] = d.ID
		byEmail[exitEmail(d)] = d.ID
		byKey[d.WGPublicKey] = d.ID
		byUUID[d.UUID] = d.ID
	}
	if r.inst != nil {
		for email, t := range r.inst.TakeTraffic() {
			if id, ok := byEmail[email]; ok {
				u := out[id]
				u.Up, u.Down = u.Up+t.Up, u.Down+t.Down
				out[id] = u
			}
		}
	}
	add := func(seen map[string]wgCounters, k string, cur wgCounters, handshake time.Time) {
		id, ok := byKey[k]
		if !ok {
			return
		}
		prev := seen[k]
		if cur.rx < prev.rx || cur.tx < prev.tx {
			prev = wgCounters{}
		}
		seen[k] = cur
		u := out[id]
		u.Up += cur.rx - prev.rx
		u.Down += cur.tx - prev.tx
		if handshake.After(u.Handshake) {
			u.Handshake = handshake
		}
		out[id] = u
	}
	if wc, err := wgctrl.New(); err == nil {
		if dev, err := wc.Device(WGInterface); err == nil {
			for _, p := range dev.Peers {
				add(r.wgSeen, p.PublicKey.String(), wgCounters{rx: p.ReceiveBytes, tx: p.TransmitBytes}, p.LastHandshakeTime)
			}
		}
		wc.Close()
	}
	if r.awg != nil {
		for k, s := range r.awg.stats() {
			var hs time.Time
			if s.handshake > 0 {
				hs = time.Unix(s.handshake, 0)
			}
			add(r.awgSeen, k, wgCounters{rx: s.rx, tx: s.tx}, hs)
		}
	}
	// IKEv2 and OpenVPN have no handshake time; a live session counts as one now.
	live := func(ids map[string]int64) func(string, int64, int64) {
		now := time.Now()
		return func(k string, rx, tx int64) {
			id, ok := ids[k]
			if !ok {
				return
			}
			u := out[id]
			u.Up, u.Down, u.Handshake = u.Up+rx, u.Down+tx, now
			out[id] = u
		}
	}
	if r.ike != nil {
		r.ike.usage(live(byEmail))
	}
	if r.ovpn != nil {
		r.ovpn.usage(live(byUUID))
	}
	if r.oc != nil {
		r.oc.usage(live(byEmail))
	}
	return out
}

// secret is a device's password for one protocol, derived from its UUID so it
// needs no column of its own.
func (r *Runtime) secret(d store.Device, label string) string {
	m := hmac.New(sha256.New, r.ikeKey)
	m.Write([]byte(label + "\x00" + d.UUID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))[:24]
}

// checkLogin finds the device a TrustTunnel username and password belong to.
func (r *Runtime) checkLogin(username, password string) (string, bool) {
	r.mu.Lock()
	want, ok := r.logins[username]
	r.mu.Unlock()
	if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(want)) != 1 {
		return "", false
	}
	return username, true
}

// dialTCP and dialUDP reach the internet for a device through Xray, so its
// rules and traffic counters cover protocols that run outside it.
func (r *Runtime) dialTCP(tag string) func(ctx context.Context, addr, email string) (net.Conn, error) {
	return func(ctx context.Context, addr, email string) (net.Conn, error) {
		r.mu.Lock()
		inst := r.inst
		r.mu.Unlock()
		if inst == nil {
			return nil, errors.New("xray is not running")
		}
		return inst.DialAs(ctx, addr, tag, email)
	}
}

func (r *Runtime) dialUDP(tag string) func(ctx context.Context, email string) (net.PacketConn, error) {
	return func(ctx context.Context, email string) (net.PacketConn, error) {
		r.mu.Lock()
		inst := r.inst
		r.mu.Unlock()
		if inst == nil {
			return nil, errors.New("xray is not running")
		}
		return inst.DialUDPAs(ctx, tag, email)
	}
}

// Front puts TrustTunnel in front of the website: HTTP/2 CONNECT with a
// device's login is tunnelled, anything else gets the site. AnyTLS shows the
// site to connections without a login too. Cloudflare's route goes first.
func (r *Runtime) Front(site http.Handler) http.Handler {
	r.mu.Lock()
	r.site = site
	r.mu.Unlock()
	var h http.Handler = &trusttunnel.Server{
		Auth:    r.checkLogin,
		DialTCP: r.dialTCP(profile.TrustTunnel),
		DialUDP: r.dialUDP(profile.TrustTunnel),
		Site:    site,
	}
	if s := r.cfg.Server; s.CloudflareAddr != "" {
		h = CloudflareFront(h, s.CloudflarePath, s.CloudflareAddr)
	}
	return h
}

// IKEServer is where IKEv2 clients connect: an IPv4-only name (see infra/main.tf).
func IKEServer(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	return "v4." + host
}

// Profile is what one device receives.
func (r *Runtime) Profile(d store.Device) profile.Profile {
	p := profile.Profile{
		Host: cmp.Or(r.cfg.MovedTo, r.cfg.Server.Host),
		WireGuard: profile.WireGuardConf{
			Port:            WGPort,
			ServerPublicKey: r.wgPub,
			Address:         []string{d.IPv4() + "/32", d.IPv6() + "/128"},
			DNS:             profile.DNS,
			MTU:             MTU,
		},
		Reality: profile.RealityConf{
			Port:      r.cfg.Server.TCPPort,
			UUID:      d.UUID,
			PublicKey: r.realityPub,
			ShortID:   r.cfg.Server.RealityShortID,
			MuxPort:   r.cfg.Server.MuxPort,
		},
	}
	if r.HasHysteria() {
		p.Hysteria2 = &profile.HysteriaConf{Port: r.cfg.Server.UDPPort, Auth: d.HysteriaAuth}
		if s := r.cfg.Server; s.ObfsPort != 0 {
			p.Hysteria2.Obfs = &profile.HysteriaObfs{Port: s.ObfsPort, Password: s.ObfsPassword, HopPorts: HopPorts}
		}
		// The site's certificate is what TrustTunnel clients verify.
		p.TrustTunnel = &profile.TrustTunnelConf{Port: r.cfg.Server.TCPPort, Username: d.Email(), Password: r.secret(d, profile.TrustTunnel)}
	}
	r.mu.Lock()
	if r.awg != nil {
		p.AmneziaWG = &profile.AmneziaConf{Port: AWGPort, Address: p.WireGuard.Address, AmneziaObfs: r.obfs}
	}
	if r.ike != nil && r.ike.cert != "" {
		p.IKEv2 = &profile.IKEv2Conf{Server: IKEServer(p.Host), RemoteID: p.Host, Username: d.Email(), Password: r.ikePassword(d)}
	}
	if r.ovpn != nil {
		if c, err := r.ovpn.clientCreds(d); err == nil {
			p.OpenVPN = &c
		}
	}
	if r.oc != nil && r.oc.cert != "" {
		p.OpenConnect = &profile.OpenConnectConf{Server: OCServer(p.Host), Port: r.cfg.Server.TCPPort, Username: d.Email(), Password: r.ikePassword(d), Secret: OCSecret(r.cfg.WGPrivateKey)}
	}
	if r.anytls != nil {
		p.AnyTLS = &profile.AnyTLSConf{Port: r.cfg.AnyTLSPort, Password: r.secret(d, profile.AnyTLS)}
	}
	if r.mieru != nil {
		p.Mieru = &profile.MieruConf{Port: r.cfg.MieruPort, Username: d.Email(), Password: r.secret(d, profile.Mieru)}
	}
	r.mu.Unlock()
	if s := r.cfg.Server; s.CloudflareAddr != "" {
		if web := CloudflareServer(p.Host); web != "" {
			p.Cloudflare = &profile.CloudflareConf{Host: web, Port: 443, Path: s.CloudflarePath, Addresses: r.cloudflareIPs(web)}
		}
	}
	if r.cfg.MovedTo == "" {
		p.IPs = r.ips
	}
	for _, a := range r.cfg.Relays {
		p.Relays = append(p.Relays, profile.Relay{Address: a, Country: profile.RelayCountry})
	}
	if r.exit() {
		p.Exit = &profile.ExitConf{UUID: r.exitUUID(d), HysteriaAuth: r.secret(d, "exit hysteria2"), Username: exitEmail(d), AnyTLSPassword: r.secret(d, "exit anytls")}
	}
	return p
}

// OpenVPNConfig is the device's .ovpn file, for OpenVPN Connect and other clients.
func (r *Runtime) OpenVPNConfig(d store.Device) (string, error) {
	r.mu.Lock()
	o := r.ovpn
	r.mu.Unlock()
	if o == nil {
		return "", errors.New("openvpn is not running")
	}
	return o.clientConfig(d)
}

func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inst != nil {
		r.inst.Close()
		r.inst = nil
	}
	if r.awg != nil {
		r.awg.close()
		r.awg = nil
	}
	if r.ike != nil {
		r.ike.sess.Close()
		r.ike = nil
	}
	if r.ovpn != nil {
		r.ovpn.close()
		r.ovpn = nil
	}
	if r.anytls != nil {
		r.anytls.close()
		r.anytls = nil
	}
	if r.mieru != nil {
		r.mieru.Close()
		r.mieru = nil
	}
}

// Loop applies the device list on every signal and at least every interval, and records usage.
func (r *Runtime) Loop(st *store.Store, kick <-chan struct{}, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	lastErr := ""
	for {
		devs, err := st.Devices(true)
		if err != nil {
			r.log.Error("devices", "err", err)
		} else {
			err := r.Apply(devs)
			if msg := fmt.Sprint(err); err != nil && msg != lastErr {
				r.log.Warn("apply", "err", err)
				lastErr = msg
			} else if err == nil {
				lastErr = ""
			}
			if u := r.TakeUsage(devs); len(u) > 0 {
				if err := st.AddUsage(u); err != nil {
					r.log.Error("usage", "err", err)
				}
			}
		}
		select {
		case <-stop:
			return
		case <-kick:
		case <-t.C:
		}
	}
}
