package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Exports for standard clients, used where the NoMax app isn't installed.

// WGConfig is a wg-quick style file for the WireGuard or AmneziaWG apps.
func (p Profile) WGConfig(protocol, privateKey string) (string, error) {
	port := p.WireGuard.Port
	var obfs string
	if protocol == AmneziaWG {
		if p.AmneziaWG == nil {
			return "", fmt.Errorf("server offers no amneziawg")
		}
		o := p.AmneziaWG.AmneziaObfs
		port = p.AmneziaWG.Port
		obfs = fmt.Sprintf("Jc = %d\nJmin = %d\nJmax = %d\nS1 = %d\nS2 = %d\nH1 = %d\nH2 = %d\nH3 = %d\nH4 = %d\n",
			o.Jc, o.Jmin, o.Jmax, o.S1, o.S2, o.H1, o.H2, o.H3, o.H4)
	} else if protocol != WireGuard {
		return "", fmt.Errorf("not a WireGuard protocol: %s", protocol)
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = %d
%s
[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, privateKey, strings.Join(p.Addresses(protocol), ", "), strings.Join(p.WireGuard.DNS, ", "), p.WireGuard.MTU, obfs,
		p.WireGuard.ServerPublicKey, net.JoinHostPort(p.Host, strconv.Itoa(port))), nil
}

// RealityURI is the vless:// share link most Xray clients import.
func (p Profile) RealityURI(name string) string {
	q := url.Values{
		"encryption": {"none"}, "flow": {VisionFlow}, "security": {"reality"}, "type": {"tcp"},
		"sni": {p.Host}, "fp": {Fingerprint}, "pbk": {p.Reality.PublicKey}, "sid": {p.Reality.ShortID},
	}
	u := url.URL{Scheme: "vless", User: url.User(p.Reality.UUID), Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Reality.Port)),
		RawQuery: q.Encode(), Fragment: name}
	return u.String()
}

// HysteriaURI is the hysteria2:// share link.
func (p Profile) HysteriaURI(name string) string {
	if p.Hysteria2 == nil {
		return ""
	}
	q := url.Values{"sni": {p.Host}}
	if p.Hysteria2.PinSHA256 != "" {
		q.Set("pinSHA256", p.Hysteria2.PinSHA256)
	}
	u := url.URL{Scheme: "hysteria2", User: url.User(p.Hysteria2.Auth), Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Hysteria2.Port)),
		Path: "/", RawQuery: q.Encode(), Fragment: name}
	return u.String()
}

// RealityMuxURI is Reality without Vision on the Mux port. Clients that can
// multiplex (Xray's mux) should turn it on; it works without.
func (p Profile) RealityMuxURI(name string) string {
	if p.Reality.MuxPort == 0 {
		return ""
	}
	q := url.Values{
		"encryption": {"none"}, "security": {"reality"}, "type": {"tcp"},
		"sni": {p.Host}, "fp": {Fingerprint}, "pbk": {p.Reality.PublicKey}, "sid": {p.Reality.ShortID},
	}
	u := url.URL{Scheme: "vless", User: url.User(p.Reality.UUID), Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Reality.MuxPort)),
		RawQuery: q.Encode(), Fragment: name}
	return u.String()
}

// HysteriaObfsURI is Hysteria2 with Salamander. mport is the hopping range;
// clients that don't hop use the port itself.
func (p Profile) HysteriaObfsURI(name string) string {
	if p.Hysteria2 == nil || p.Hysteria2.Obfs == nil {
		return ""
	}
	o := p.Hysteria2.Obfs
	q := url.Values{"sni": {p.Host}, "obfs": {"salamander"}, "obfs-password": {o.Password}}
	if o.HopPorts != "" {
		q.Set("mport", o.HopPorts)
	}
	u := url.URL{Scheme: "hysteria2", User: url.User(p.Hysteria2.Auth), Host: net.JoinHostPort(p.Host, strconv.Itoa(o.Port)),
		Path: "/", RawQuery: q.Encode(), Fragment: name}
	return u.String()
}

// AnyTLSURI is the anytls:// link that sing-box and mihomo clients import.
func (p Profile) AnyTLSURI(name string) string {
	if p.AnyTLS == nil {
		return ""
	}
	u := url.URL{Scheme: "anytls", User: url.User(p.AnyTLS.Password), Host: net.JoinHostPort(p.Host, strconv.Itoa(p.AnyTLS.Port)),
		Path: "/", RawQuery: url.Values{"sni": {p.Host}}.Encode(), Fragment: name}
	return u.String()
}

// MieruURI is Mieru's simple mierus:// link, with the settings the app uses.
func (p Profile) MieruURI() string {
	if p.Mieru == nil {
		return ""
	}
	m := p.Mieru
	q := url.Values{
		"profile": {"nomax"}, "multiplexing": {"MULTIPLEXING_HIGH"}, "handshake-mode": {"HANDSHAKE_NO_WAIT"},
		"port": {strconv.Itoa(m.Port)}, "protocol": {"TCP"},
	}
	u := url.URL{Scheme: "mierus", User: url.UserPassword(m.Username, m.Password), Host: p.Host, RawQuery: q.Encode()}
	return u.String()
}

// MobileConfig is an Apple configuration profile for the built-in IKEv2 client
// (iPhone, iPad, Mac), with the same algorithms the NoMax app asks for.
func (p Profile) MobileConfig(name string) ([]byte, error) {
	if p.IKEv2 == nil {
		return nil, fmt.Errorf("server offers no ikev2")
	}
	i := p.IKEv2
	esc := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	sa := `<dict>
				<key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
				<key>IntegrityAlgorithm</key><string>SHA2-384</string>
				<key>DiffieHellmanGroup</key><integer>20</integer>
			</dict>`
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDisplayName</key><string>NoMax (%[1]s)</string>
	<key>PayloadIdentifier</key><string>chat.nomax.%[2]s</string>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>%[3]s</string>
	<key>PayloadVersion</key><integer>1</integer>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadDisplayName</key><string>NoMax IKEv2</string>
			<key>PayloadIdentifier</key><string>chat.nomax.%[2]s.vpn</string>
			<key>PayloadType</key><string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key><string>%[4]s</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>UserDefinedName</key><string>NoMax (IKEv2)</string>
			<key>VPNType</key><string>IKEv2</string>
			<key>IKEv2</key>
			<dict>
				<key>RemoteAddress</key><string>%[5]s</string>
				<key>RemoteIdentifier</key><string>%[6]s</string>
				<key>LocalIdentifier</key><string>%[7]s</string>
				<key>AuthenticationMethod</key><string>None</string>
				<key>ExtendedAuthEnabled</key><integer>1</integer>
				<key>AuthName</key><string>%[7]s</string>
				<key>AuthPassword</key><string>%[8]s</string>
				<key>EnablePFS</key><integer>1</integer>
				<key>DisconnectOnIdle</key><integer>0</integer>
				<key>IKESecurityAssociationParameters</key>
			%[9]s
				<key>ChildSecurityAssociationParameters</key>
			%[9]s
			</dict>
		</dict>
	</array>
</dict>
</plist>
`, esc(name), esc(i.Username), uuid4(), uuid4(), esc(i.Server), esc(i.RemoteID), esc(i.Username), esc(i.Password), sa), nil
}

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
