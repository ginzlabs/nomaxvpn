// Package profile is the contract between the server and the iOS tunnel:
// the JSON a device receives, and the Xray configs both ends run. Server and
// client configs are built here, from the same types, so they cannot drift.
package profile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	WireGuard = "wireguard"
	AmneziaWG = "amneziawg"
	Reality   = "reality"
	Hysteria2 = "hysteria2"
	// IKEv2 uses the platform's own client, so the Go core never runs it.
	IKEv2 = "ikev2"
	// OpenVPN and OpenConnect (Cisco AnyConnect's protocol) run in the Go core
	// too, and standard clients (OpenVPN Connect, Cisco Secure Client) also work.
	OpenVPN     = "openvpn"
	OpenConnect = "openconnect"
	// RealityMux is Reality on its own port without Vision and with Xray's
	// mux on, so the apps' connections share a few TLS sessions.
	RealityMux = "realitymux"
	// Hysteria2Obfs wraps Hysteria2 in Salamander, so it no longer looks like
	// QUIC, and hops across a range of UDP ports.
	Hysteria2Obfs = "hysteria2obfs"
	// TrustTunnel is HTTP/2 CONNECT to the website, with a password.
	TrustTunnel = "trusttunnel"
	// AnyTLS pads TLS so its record sizes don't give away the TLS inside.
	AnyTLS = "anytls"
	// Mieru is an encrypted stream with no handshake pattern to match.
	Mieru = "mieru"
	// Cloudflare is VLESS over WebSocket to the website's name behind
	// Cloudflare's proxy, for networks that cut the server's own address.
	Cloudflare = "cloudflare"

	VisionFlow = "xtls-rprx-vision"
	// Fingerprint is the TLS ClientHello Reality imitates. Some filters
	// single out uTLS's Chrome one.
	Fingerprint = "firefox"
)

// Protocols lists the protocols the Go core runs, in the order Auto tries
// them: UDP first, then TCP without TLS, then TLS on 443, where some
// filters freeze connections and count handshakes, and Cloudflare's route
// last, for when nothing reaches the server directly.
var Protocols = []string{
	WireGuard, AmneziaWG, Hysteria2, Hysteria2Obfs, OpenVPN,
	Mieru, TrustTunnel, OpenConnect, RealityMux, AnyTLS, Reality, Cloudflare,
}

var titles = map[string]string{
	WireGuard: "WireGuard", AmneziaWG: "AmneziaWG", Reality: "Reality", RealityMux: "Reality Mux",
	Hysteria2: "Hysteria2", Hysteria2Obfs: "Hysteria2 Obfs", OpenVPN: "OpenVPN",
	OpenConnect: "Cisco AnyConnect", TrustTunnel: "TrustTunnel", AnyTLS: "AnyTLS", Mieru: "Mieru", IKEv2: "IKEv2",
	Cloudflare: "Cloudflare",
}

// Title is the protocol's display name.
func Title(protocol string) string {
	if t, ok := titles[protocol]; ok {
		return t
	}
	return protocol
}

// Offered reports whether the profile has what protocol needs.
func Offered(p Profile, protocol string) bool {
	switch protocol {
	case WireGuard:
		return p.WireGuard.ServerPublicKey != ""
	case Reality:
		return true
	case AmneziaWG:
		return p.AmneziaWG != nil
	case Hysteria2:
		return p.Hysteria2 != nil
	case Hysteria2Obfs:
		return p.Hysteria2 != nil && p.Hysteria2.Obfs != nil
	case RealityMux:
		return p.Reality.MuxPort != 0
	case OpenVPN:
		return p.OpenVPN != nil && p.OpenVPN.Cert != ""
	case OpenConnect:
		return p.OpenConnect != nil
	case TrustTunnel:
		return p.TrustTunnel != nil
	case AnyTLS:
		return p.AnyTLS != nil
	case Mieru:
		return p.Mieru != nil
	case Cloudflare:
		return p.Cloudflare != nil
	case IKEv2:
		return p.IKEv2 != nil
	}
	return false
}

// APIPath is the device API's secret first path segment. The apps get it at
// build time (-X github.com/ginzlabs/nomaxvpn/internal/profile.APIPath=…, from
// API_PATH); the server gets API_PATH itself. Empty is "api".
var APIPath string

// API is the device API's base path: "/api/v1" unless APIPath is set.
func API() string { return APIBase(APIPath) }

// APIBase is the API's base path for a given secret segment.
func APIBase(path string) string {
	if path = strings.Trim(path, "/"); path == "" {
		path = "api"
	}
	return "/" + path + "/v1"
}

// Profile is what GET {API}/profile returns to a device.
type Profile struct {
	Host      string        `json:"host"`
	WireGuard WireGuardConf `json:"wireguard"`
	AmneziaWG *AmneziaConf  `json:"amneziawg,omitempty"`
	Reality   RealityConf   `json:"reality"`
	Hysteria2 *HysteriaConf `json:"hysteria2,omitempty"`
	IKEv2     *IKEv2Conf    `json:"ikev2,omitempty"`
	OpenVPN   *OpenVPNConf  `json:"openvpn,omitempty"`
	// OpenConnect is ocserv, which speaks Cisco AnyConnect's protocol.
	OpenConnect *OpenConnectConf `json:"openconnect,omitempty"`
	TrustTunnel *TrustTunnelConf `json:"trusttunnel,omitempty"`
	AnyTLS      *AnyTLSConf      `json:"anytls,omitempty"`
	Mieru       *MieruConf       `json:"mieru,omitempty"`
	Cloudflare  *CloudflareConf  `json:"cloudflare,omitempty"`
	// IPs are the server's own addresses, so apps needn't trust DNS for them.
	IPs []string `json:"ips,omitempty"`
	// Relays forward every port to the server from another country's address,
	// for networks that block the server's. Cloudflare's route doesn't use them.
	Relays []Relay `json:"relays,omitempty"`
	// Exit is the device's second login, whose traffic leaves the server
	// through the first relay (WithExit).
	Exit *ExitConf `json:"exit,omitempty"`
}

// Relay is a machine that forwards every protocol's port to the server.
type Relay struct {
	Address string `json:"address"`
	Country string `json:"country"`
}

// RelayCountry is the relays' country code. Auto goes through a relay first
// on networks there.
const RelayCountry = ""

// ExitConf is the device's login for traffic that leaves through the first
// relay. AnyTLS has no usernames, so it gets a password of its own.
type ExitConf struct {
	UUID           string `json:"uuid"`
	HysteriaAuth   string `json:"hysteriaAuth"`
	Username       string `json:"username"`
	AnyTLSPassword string `json:"anytlsPassword"`
}

// WithExit is the profile with the device's exit login in place of its own,
// and false when the server offers no exit. Only what Xray carries on the
// server can leave through the relay, so the other protocols drop out.
func (p Profile) WithExit() (Profile, bool) {
	e := p.Exit
	if e == nil {
		return p, false
	}
	q := p
	q.Reality.UUID = e.UUID
	if h := p.Hysteria2; h != nil {
		c := *h
		c.Auth = e.HysteriaAuth
		q.Hysteria2 = &c
	}
	if t := p.TrustTunnel; t != nil {
		c := *t
		c.Username = e.Username
		q.TrustTunnel = &c
	}
	if m := p.Mieru; m != nil {
		c := *m
		c.Username = e.Username
		q.Mieru = &c
	}
	if a := p.AnyTLS; a != nil {
		c := *a
		c.Password = e.AnyTLSPassword
		q.AnyTLS = &c
	}
	q.WireGuard.ServerPublicKey, q.WireGuard.Port = "", 0
	q.AmneziaWG, q.OpenVPN, q.OpenConnect, q.IKEv2 = nil, nil, nil, nil
	return q, true
}

// CloudflareConf is where VLESS over WebSocket reaches the server through
// Cloudflare: the website's name behind Cloudflare's proxy, and the path its
// WebSocket listens on. The device's UUID is Reality's.
type CloudflareConf struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
	// Addresses are Cloudflare's for Host, so the tunnel connects without a
	// DNS lookup. Any of Cloudflare's addresses serves the name.
	Addresses []string `json:"addresses,omitempty"`
	// PinSHA256 pins the certificate (hex) instead of verifying it (tests).
	PinSHA256 string `json:"pinSHA256,omitempty"`
}

// address is where to connect: an IPv4 address of Cloudflare's if there is one.
func (c CloudflareConf) address() string {
	for _, a := range c.Addresses {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(c.Addresses) > 0 {
		return c.Addresses[0]
	}
	return c.Host
}

// TrustTunnelConf is a login for HTTP/2 CONNECT on the website (Host, Port).
type TrustTunnelConf struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AnyTLSConf is AnyTLS on its own port, behind the site's certificate.
type AnyTLSConf struct {
	Port     int    `json:"port"`
	Password string `json:"password"`
}

// MieruConf is a Mieru login. Mieru has no certificate; the password keys it.
type MieruConf struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AmneziaConf is WireGuard with junk packets, padded handshakes and changed
// message headers. It shares the WireGuard keys, DNS and MTU.
type AmneziaConf struct {
	Port    int      `json:"port"`
	Address []string `json:"address"`
	AmneziaObfs
}

// AmneziaObfs are the AmneziaWG 1.0 parameters; both ends must match.
type AmneziaObfs struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
}

// AmneziaParams derives stable obfuscation parameters from a server secret,
// so they need no configuration of their own.
func AmneziaParams(secret string) AmneziaObfs {
	b := sha256.Sum256([]byte("nomax amneziawg\x00" + secret))
	o := AmneziaObfs{
		Jc:   4 + int(b[0]%5),
		Jmin: 40 + int(b[1]%30),
		S1:   15 + int(b[2]%100),
		S2:   15 + int(b[3]%100),
	}
	o.Jmax = o.Jmin + 200 + int(b[4])*2
	if o.S1+56 == o.S2 {
		o.S2++
	}
	seen := map[uint32]bool{1: true, 2: true, 3: true, 4: true}
	hs := []*uint32{&o.H1, &o.H2, &o.H3, &o.H4}
	for i, h := range hs {
		v := binary.BigEndian.Uint32(b[8+4*i:])
		for seen[v] || v < 5 {
			v = v*2654435761 + 1
		}
		seen[v], *h = true, v
	}
	return o
}

// UAPI renders the parameters as wireguard-go/amneziawg-go device keys.
func (o AmneziaObfs) UAPI() string {
	return fmt.Sprintf("jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		o.Jc, o.Jmin, o.Jmax, o.S1, o.S2, o.H1, o.H2, o.H3, o.H4)
}

type WireGuardConf struct {
	Port            int      `json:"port"`
	ServerPublicKey string   `json:"serverPublicKey"`
	Address         []string `json:"address"`
	DNS             []string `json:"dns"`
	MTU             int      `json:"mtu"`
}

type RealityConf struct {
	Port      int    `json:"port"`
	UUID      string `json:"uuid"`
	PublicKey string `json:"publicKey"`
	ShortID   string `json:"shortId"`
	// MuxPort is Reality Mux, the same keys and UUID without Vision.
	MuxPort int `json:"muxPort,omitempty"`
}

type HysteriaConf struct {
	Port int    `json:"port"`
	Auth string `json:"auth"`
	// PinSHA256 pins the server certificate (hex). Empty means normal CA verification.
	PinSHA256 string `json:"pinSHA256,omitempty"`
	// Obfs is Hysteria2 Obfs: the same login, Salamander-wrapped, on its own ports.
	Obfs *HysteriaObfs `json:"obfs,omitempty"`
}

// HysteriaObfs is Salamander's password and where to send: Port, or any port
// in HopPorts ("20000-20999"), changing every so often.
type HysteriaObfs struct {
	Port     int    `json:"port"`
	Password string `json:"password"`
	HopPorts string `json:"hopPorts,omitempty"`
}

// OpenVPNConf is the device's OpenVPN identity: the CA to trust, its own
// certificate and key, and the tls-crypt key (all PEM). OpenVPN Connect gets
// the same as an .ovpn from GET {API}/openvpn.
type OpenVPNConf struct {
	Port     int    `json:"port"`
	CA       string `json:"ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	TLSCrypt string `json:"tlsCrypt"`
}

// OpenConnectConf is an AnyConnect login. The server's Let's Encrypt
// certificate authenticates it, the password authenticates the device.
type OpenConnectConf struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Secret goes in the first request's query ("/?secret"); without it the
	// server answers 404.
	Secret string `json:"secret,omitempty"`
}

// IKEv2Conf is for the built-in IKEv2 clients: the server's Let's Encrypt
// certificate authenticates it, EAP-MSCHAPv2 authenticates the device.
type IKEv2Conf struct {
	Server   string `json:"server"`
	RemoteID string `json:"remoteId"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DNS servers handed to every tunnel.
var DNS = []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"}

// PrivateRanges are the addresses no device may reach through the server.
var PrivateRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.168.0.0/16", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8",
}

// Server holds what the server side needs to build its Xray config.
type Server struct {
	Host              string
	RealityPrivateKey string
	RealityShortID    string
	// RealityTarget is where non-Reality TLS on :443 goes: the panel's own TLS listener.
	RealityTarget string
	TCPPort       int
	UDPPort       int
	// MuxPort runs Reality Mux (no Vision, so clients can mux). 0 means off.
	MuxPort int
	// ObfsPort runs Hysteria2 again, Salamander-wrapped with ObfsPassword. 0 means off.
	ObfsPort     int
	ObfsPassword string
	// Hysteria2 runs only when a certificate is available.
	CertPEM, KeyPEM string
	// MasqueradeURL is what Hysteria2 shows to HTTP/3 probes.
	MasqueradeURL string
	// CloudflareAddr is VLESS over WebSocket on the loopback, for the website
	// to hand Cloudflare's WebSocket connections on CloudflarePath. Empty means off.
	CloudflareAddr, CloudflarePath string
	// Listen is the bind address; empty means all interfaces.
	Listen string
	// AllowPrivate lets clients reach private and loopback ranges (tests only).
	AllowPrivate bool
	// ExitVia is the address the exit logins' connections leave from (the
	// server's end of the relay link, which policy routing sends to the
	// relay), and ExitEmails are those logins. Empty means no exit.
	ExitVia    string
	ExitEmails []string
}

// Device is one enrolled device as the Xray server sees it.
type Device struct {
	Email        string
	UUID         string
	HysteriaAuth string
}

type obj = map[string]any

// ServerXray renders the server's Xray config: VLESS+Reality+Vision on TCP and,
// with a certificate, Hysteria2 on UDP. Access logs stay off.
func ServerXray(s Server, devices []Device) ([]byte, error) {
	if s.Host == "" || s.RealityPrivateKey == "" || s.RealityTarget == "" {
		return nil, errors.New("profile: server host, reality key and target are required")
	}
	visionClients := []obj{}
	muxClients := []obj{}
	hyClients := []obj{}
	for _, d := range devices {
		visionClients = append(visionClients, obj{"id": d.UUID, "flow": VisionFlow, "email": d.Email})
		muxClients = append(muxClients, obj{"id": d.UUID, "email": d.Email})
		hyClients = append(hyClients, obj{"auth": d.HysteriaAuth, "email": d.Email})
	}
	sniff := obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	reality := func(tag string, port int, clients []obj) obj {
		return obj{
			"tag":      tag,
			"listen":   s.Listen,
			"port":     port,
			"protocol": "vless",
			"settings": obj{"clients": clients, "decryption": "none"},
			"streamSettings": obj{
				"network":  "raw",
				"security": "reality",
				"realitySettings": obj{
					"target":      s.RealityTarget,
					"xver":        1,
					"serverNames": []string{s.Host},
					"privateKey":  s.RealityPrivateKey,
					"shortIds":    []string{s.RealityShortID},
				},
			},
			"sniffing": sniff,
		}
	}
	inbounds := []obj{reality("reality", s.TCPPort, visionClients)}
	if s.MuxPort != 0 {
		inbounds = append(inbounds, reality(RealityMux, s.MuxPort, muxClients))
	}
	if s.CertPEM != "" && s.KeyPEM != "" {
		hy := obj{"version": 2}
		if s.MasqueradeURL != "" {
			hy["masquerade"] = obj{"type": "proxy", "url": s.MasqueradeURL, "rewriteHost": true, "insecure": true}
		}
		hysteria := func(tag string, port int) obj {
			return obj{
				"tag":      tag,
				"listen":   s.Listen,
				"port":     port,
				"protocol": "hysteria",
				"settings": obj{"version": 2, "clients": hyClients},
				"streamSettings": obj{
					"network":  "hysteria",
					"security": "tls",
					"tlsSettings": obj{
						"alpn":         []string{"h3"},
						"certificates": []obj{{"certificate": lines(s.CertPEM), "key": lines(s.KeyPEM)}},
					},
					"hysteriaSettings": hy,
				},
				"sniffing": sniff,
			}
		}
		inbounds = append(inbounds, hysteria("hysteria2", s.UDPPort))
		if s.ObfsPort != 0 && s.ObfsPassword != "" {
			in := hysteria(Hysteria2Obfs, s.ObfsPort)
			in["streamSettings"].(obj)["finalmask"] = obj{"udp": []obj{salamander(s.ObfsPassword)}}
			inbounds = append(inbounds, in)
		}
	}
	if s.CloudflareAddr != "" {
		host, port, err := net.SplitHostPort(s.CloudflareAddr)
		if err != nil {
			return nil, fmt.Errorf("profile: cloudflare listener: %w", err)
		}
		n, _ := strconv.Atoi(port)
		inbounds = append(inbounds, obj{
			"tag":            Cloudflare,
			"listen":         host,
			"port":           n,
			"protocol":       "vless",
			"settings":       obj{"clients": muxClients, "decryption": "none"},
			"streamSettings": obj{"network": "ws", "wsSettings": obj{"path": s.CloudflarePath}},
			"sniffing":       sniff,
		})
	}
	// Freedom blocks private and loopback targets (after DNS) on its own only
	// for its own inbounds' protocols; TrustTunnel, AnyTLS and Mieru dial in
	// through the API, so the rules list those ranges too.
	final := []obj{{"action": "block", "port": "25"}, {"action": "block", "ip": PrivateRanges}}
	if s.AllowPrivate {
		final = append([]obj{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}, final...)
	}
	cfg := obj{
		"log":   obj{"loglevel": "warning", "access": "none", "dnsLog": false},
		"stats": obj{},
		"policy": obj{
			"levels": obj{"0": obj{"statsUserUplink": true, "statsUserDownlink": true, "handshake": 8, "connIdle": 300}},
		},
		"inbounds":  inbounds,
		"outbounds": []obj{{"tag": "direct", "protocol": "freedom", "settings": obj{"finalRules": final}}},
	}
	if s.ExitVia != "" && len(s.ExitEmails) > 0 {
		// The link is IPv4, so names resolve to IPv4 addresses.
		cfg["outbounds"] = append(cfg["outbounds"].([]obj), obj{
			"tag": "exit", "protocol": "freedom", "sendThrough": s.ExitVia,
			"settings": obj{"domainStrategy": "UseIPv4", "finalRules": final},
		})
		cfg["routing"] = obj{"rules": []obj{{"type": "field", "user": s.ExitEmails, "outboundTag": "exit"}}}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ClientInbound selects how traffic enters the client: the iOS tunnel fd
// (TunMTU set) or a local SOCKS port (tests and `ops probe`).
type ClientInbound struct {
	TunMTU    int
	SocksPort int
	// Address overrides where to connect; the TLS server name stays Profile.Host.
	// Cloudflare's route ignores it: it connects to Cloudflare, not the server.
	Address string
	// Tun makes Xray create and route the interface itself (Windows), instead
	// of using one the OS handed over.
	Tun *SystemTun
	// WireGuardKey is the device key, for WireGuard through Xray's own client.
	WireGuardKey string
	// BridgePort is the local SOCKS5 bridge for TrustTunnel, AnyTLS and Mieru,
	// and on Windows for the protocols that run on a userspace network stack.
	// Everything then goes to the bridge, whatever the protocol.
	BridgePort int
}

// SystemTun is an interface Xray sets up: addresses, DNS, and routes for
// everything, with Xray's own connections bound to the physical interface.
type SystemTun struct {
	Name    string
	Gateway []string // interface addresses, CIDR
	DNS     []string
	Routes  []string
	// BlockLeaks lists what Windows' firewall keeps from leaving outside the
	// interface, e.g. "dns".
	BlockLeaks []string
}

// ClientXray renders the device's Xray config for Reality, Hysteria2 or
// Cloudflare's route, or WireGuard through Xray's client where no WireGuard
// engine runs (Windows).
func ClientXray(p Profile, protocol string, in ClientInbound) ([]byte, error) {
	var inbound obj
	switch {
	case in.TunMTU > 0 && in.Tun != nil:
		inbound = obj{"tag": "tun", "protocol": "tun", "port": 0, "settings": obj{
			"name":                   in.Tun.Name,
			"mtu":                    in.TunMTU,
			"gateway":                in.Tun.Gateway,
			"dns":                    in.Tun.DNS,
			"autoSystemRoutingTable": in.Tun.Routes,
			"autoSystemWfpBlockLeak": in.Tun.BlockLeaks,
		}}
	case in.TunMTU > 0:
		inbound = obj{"tag": "tun", "protocol": "tun", "port": 0, "settings": obj{"name": "utun", "mtu": in.TunMTU}}
	case in.SocksPort > 0:
		inbound = obj{"tag": "socks", "listen": "127.0.0.1", "port": in.SocksPort, "protocol": "socks", "settings": obj{"udp": true}}
	default:
		return nil, errors.New("profile: client inbound required")
	}
	addr := p.Host
	if in.Address != "" {
		addr = in.Address
	}
	var proxy obj
	switch {
	case in.BridgePort > 0:
		proxy = obj{
			"tag":      "proxy",
			"protocol": "socks",
			"settings": obj{"servers": []obj{{"address": "127.0.0.1", "port": in.BridgePort}}},
		}
	case protocol == TrustTunnel, protocol == AnyTLS, protocol == Mieru:
		return nil, fmt.Errorf("profile: %s goes through the local bridge", protocol)
	case protocol == Reality, protocol == RealityMux:
		r := p.Reality
		user := obj{"id": r.UUID, "flow": VisionFlow, "encryption": "none"}
		port := r.Port
		if protocol == RealityMux {
			if r.MuxPort == 0 {
				return nil, errors.New("profile: server offers no reality mux")
			}
			delete(user, "flow")
			port = r.MuxPort
		}
		proxy = obj{
			"tag":      "proxy",
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{"address": addr, "port": port, "users": []obj{user}}}},
			"streamSettings": obj{
				"network":  "raw",
				"security": "reality",
				"realitySettings": obj{
					"serverName":  p.Host,
					"fingerprint": Fingerprint,
					"publicKey":   r.PublicKey,
					"shortId":     r.ShortID,
				},
			},
		}
		if protocol == RealityMux {
			// QUIC to port 443 is refused so apps fall back to TCP, which the mux carries.
			proxy["mux"] = obj{"enabled": true, "concurrency": 8, "xudpConcurrency": 8, "xudpProxyUDP443": "reject"}
		}
	case protocol == Cloudflare:
		c := p.Cloudflare
		if c == nil {
			return nil, errors.New("profile: server offers no cloudflare route")
		}
		tls := obj{"serverName": c.Host, "fingerprint": Fingerprint}
		if c.PinSHA256 != "" {
			tls["pinnedPeerCertSha256"] = c.PinSHA256
		}
		proxy = obj{
			"tag":      "proxy",
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{"address": c.address(), "port": c.Port, "users": []obj{{"id": p.Reality.UUID, "encryption": "none"}}}}},
			"streamSettings": obj{
				"network":     "ws",
				"security":    "tls",
				"tlsSettings": tls,
				// Pings keep idle connections from being closed by Cloudflare.
				"wsSettings": obj{"path": c.Path, "host": c.Host, "heartbeatPeriod": 30},
			},
		}
	case protocol == Hysteria2, protocol == Hysteria2Obfs:
		h := p.Hysteria2
		if h == nil {
			return nil, errors.New("profile: server offers no hysteria2")
		}
		tls := obj{"serverName": p.Host, "alpn": []string{"h3"}}
		if h.PinSHA256 != "" {
			tls["pinnedPeerCertSha256"] = h.PinSHA256
		}
		stream := obj{
			"network":          "hysteria",
			"security":         "tls",
			"tlsSettings":      tls,
			"hysteriaSettings": obj{"version": 2, "auth": h.Auth},
		}
		port := h.Port
		if protocol == Hysteria2Obfs {
			if h.Obfs == nil {
				return nil, errors.New("profile: server offers no hysteria2 obfs")
			}
			port = h.Obfs.Port
			masks := []obj{salamander(h.Obfs.Password)}
			if h.Obfs.HopPorts != "" {
				// A new socket and port every 30 s or so. Masks run last to
				// first, and the hop has to be the one next to the socket.
				masks = append(masks, obj{"type": "udphop", "settings": obj{
					"mode": "intervalLocal,intervalRemote", "remotePorts": h.Obfs.HopPorts,
				}})
			}
			stream["finalmask"] = obj{"udp": masks}
		}
		proxy = obj{
			"tag":            "proxy",
			"protocol":       "hysteria",
			"settings":       obj{"version": 2, "address": addr, "port": port},
			"streamSettings": stream,
		}
	case protocol == WireGuard:
		if in.WireGuardKey == "" {
			return nil, errors.New("profile: wireguard through xray needs the device key")
		}
		w := p.WireGuard
		proxy = obj{
			"tag":      "proxy",
			"protocol": "wireguard",
			"settings": obj{
				"secretKey":   in.WireGuardKey,
				"address":     w.Address,
				"mtu":         w.MTU,
				"noKernelTun": true,
				"peers": []obj{{
					"publicKey":  w.ServerPublicKey,
					"endpoint":   net.JoinHostPort(addr, strconv.Itoa(w.Port)),
					"keepAlive":  25,
					"allowedIPs": []string{"0.0.0.0/0", "::/0"},
				}},
			},
		}
	default:
		return nil, fmt.Errorf("profile: %q is not an Xray protocol", protocol)
	}
	cfg := obj{
		"log":       obj{"loglevel": "warning", "access": "none", "dnsLog": false},
		"stats":     obj{},
		"policy":    obj{"system": obj{"statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"inbounds":  []obj{inbound},
		"outbounds": []obj{proxy},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// WireGuardUAPI renders the amneziawg-go IPC config for a device, for plain
// WireGuard or AmneziaWG. serverIP must be an address; the engine does not resolve names.
func WireGuardUAPI(p Profile, protocol, privateKey, serverIP string) (string, error) {
	priv, err := keyHex(privateKey)
	if err != nil {
		return "", fmt.Errorf("profile: private key: %w", err)
	}
	pub, err := keyHex(p.WireGuard.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("profile: server key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	port := p.WireGuard.Port
	switch protocol {
	case WireGuard:
	case AmneziaWG:
		if p.AmneziaWG == nil {
			return "", errors.New("profile: server offers no amneziawg")
		}
		b.WriteString(p.AmneziaWG.UAPI())
		port = p.AmneziaWG.Port
	default:
		return "", fmt.Errorf("profile: %q is not a WireGuard protocol", protocol)
	}
	endpoint := serverIP + ":" + fmt.Sprint(port)
	if strings.Contains(serverIP, ":") {
		endpoint = "[" + serverIP + "]:" + fmt.Sprint(port)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\n", pub, endpoint)
	b.WriteString("replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
	return b.String(), nil
}

// Addresses returns the tunnel addresses for a WireGuard protocol.
func (p Profile) Addresses(protocol string) []string {
	if protocol == AmneziaWG && p.AmneziaWG != nil {
		return p.AmneziaWG.Address
	}
	return p.WireGuard.Address
}

func keyHex(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(k) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	return hex.EncodeToString(k), nil
}

func salamander(password string) obj {
	return obj{"type": "salamander", "settings": obj{"password": password}}
}

func lines(pem string) []string {
	return strings.Split(strings.TrimSpace(pem), "\n")
}
