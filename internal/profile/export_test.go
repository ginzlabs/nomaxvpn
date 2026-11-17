package profile_test

import (
	"encoding/xml"
	"net/url"
	"strings"
	"testing"

	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func exportProfile(t *testing.T) (profile.Profile, string) {
	srv := profile.NewWireGuardKey()
	pub, err := profile.WireGuardPublic(srv)
	must(t, err)
	addr := []string{"10.8.0.7/32", "fd08::7/128"}
	return profile.Profile{
		Host:      "vpn.test",
		WireGuard: profile.WireGuardConf{Port: 51820, ServerPublicKey: pub, Address: addr, DNS: profile.DNS, MTU: 1280},
		AmneziaWG: &profile.AmneziaConf{Port: 51821, Address: addr, AmneziaObfs: profile.AmneziaParams(srv)},
		Reality:   profile.RealityConf{Port: 443, UUID: "6f1c2b9e-0000-4000-8000-000000000001", PublicKey: "pbk", ShortID: "ab12", MuxPort: 2053},
		Hysteria2: &profile.HysteriaConf{Port: 443, Auth: "s3cret", Obfs: &profile.HysteriaObfs{Port: 8443, Password: "salt", HopPorts: "20000-20999"}},
		IKEv2:     &profile.IKEv2Conf{Server: "vpn.test", RemoteID: "vpn.test", Username: "d7", Password: "p<w>&"},
		AnyTLS:    &profile.AnyTLSConf{Port: 2083, Password: "any"},
		Mieru:     &profile.MieruConf{Port: 2096, Username: "d7", Password: "mieru-pw"},
	}, profile.NewWireGuardKey()
}

func TestWGConfig(t *testing.T) {
	p, key := exportProfile(t)
	wg, err := p.WGConfig(profile.WireGuard, key)
	must(t, err)
	for _, want := range []string{"PrivateKey = " + key, "Address = 10.8.0.7/32, fd08::7/128", "Endpoint = vpn.test:51820", "AllowedIPs = 0.0.0.0/0, ::/0"} {
		if !strings.Contains(wg, want) {
			t.Fatalf("wireguard conf lacks %q:\n%s", want, wg)
		}
	}
	if strings.Contains(wg, "Jc =") {
		t.Fatal("plain WireGuard conf has AmneziaWG fields")
	}
	awg, err := p.WGConfig(profile.AmneziaWG, key)
	must(t, err)
	if !strings.Contains(awg, "Endpoint = vpn.test:51821") || !strings.Contains(awg, "H4 = ") {
		t.Fatalf("amneziawg conf:\n%s", awg)
	}
}

func TestShareLinks(t *testing.T) {
	p, _ := exportProfile(t)
	u, err := url.Parse(p.RealityURI("NoMax"))
	must(t, err)
	q := u.Query()
	if u.Scheme != "vless" || u.User.Username() != p.Reality.UUID || u.Host != "vpn.test:443" ||
		q.Get("security") != "reality" || q.Get("pbk") != "pbk" || q.Get("sid") != "ab12" || q.Get("flow") != profile.VisionFlow || u.Fragment != "NoMax" {
		t.Fatalf("reality link: %s", u)
	}
	h, err := url.Parse(p.HysteriaURI("NoMax"))
	must(t, err)
	if h.Scheme != "hysteria2" || h.User.Username() != "s3cret" || h.Query().Get("sni") != "vpn.test" {
		t.Fatalf("hysteria2 link: %s", h)
	}
	m, err := url.Parse(p.RealityMuxURI("NoMax"))
	must(t, err)
	if m.Host != "vpn.test:2053" || m.Query().Has("flow") || m.Query().Get("pbk") != "pbk" {
		t.Fatalf("reality mux link: %s", m)
	}
	o, err := url.Parse(p.HysteriaObfsURI("NoMax"))
	must(t, err)
	if oq := o.Query(); o.Host != "vpn.test:8443" || oq.Get("obfs") != "salamander" || oq.Get("obfs-password") != "salt" || oq.Get("mport") != "20000-20999" {
		t.Fatalf("hysteria2 obfs link: %s", o)
	}
	a, err := url.Parse(p.AnyTLSURI("NoMax"))
	must(t, err)
	if a.Scheme != "anytls" || a.User.Username() != "any" || a.Host != "vpn.test:2083" || a.Query().Get("sni") != "vpn.test" {
		t.Fatalf("anytls link: %s", a)
	}
	mp, err := appctl.URLToClientProfile(p.MieruURI())
	must(t, err)
	if mp.GetUser().GetName() != "d7" || mp.GetUser().GetPassword() != "mieru-pw" || mp.GetServers()[0].GetDomainName() != "vpn.test" ||
		mp.GetServers()[0].GetPortBindings()[0].GetPort() != 2096 {
		t.Fatalf("mieru link %s gives %v", p.MieruURI(), mp)
	}
}

func TestMobileConfig(t *testing.T) {
	p, _ := exportProfile(t)
	b, err := p.MobileConfig("Ann's Mac")
	must(t, err)
	var v any
	if err := xml.Unmarshal(b, &v); err != nil {
		t.Fatalf("not XML: %v", err)
	}
	if !strings.Contains(string(b), "<string>p&lt;w&gt;&amp;</string>") || !strings.Contains(string(b), "Ann&#39;s Mac") {
		t.Fatalf("values not escaped:\n%s", b)
	}
}
