package profile_test

import (
	"encoding/json"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
)

// TestExitRouting runs a server whose exit leaves from an address this
// machine doesn't have: the device's own login gets through, its exit login
// is routed to the exit and fails.
func TestExitRouting(t *testing.T) {
	dest := serveHTTP(t, "hello through the tunnel")
	certPEM, keyPEM, err := tlsutil.SelfSigned(host)
	must(t, err)
	decoy := serveDecoy(t, certPEM, keyPEM)
	tcpPort := freeTCP(t)
	realityKey := profile.NewRealityKey()
	realityPub, err := profile.RealityPublic(realityKey)
	must(t, err)
	shortID := profile.RandomHex(8)
	dev := profile.Device{Email: "d1", UUID: "6a3c9f8e-5b2d-4c1a-9e7f-0d8b2a4c6e1f", HysteriaAuth: profile.RandomToken(24)}
	twin := profile.Device{Email: "d1x", UUID: "0b7e2f4a-1c3d-4e5f-8a9b-c0d1e2f3a4b5", HysteriaAuth: profile.RandomToken(24)}
	srvCfg, err := profile.ServerXray(profile.Server{
		Host: host, RealityPrivateKey: realityKey, RealityShortID: shortID, RealityTarget: decoy,
		TCPPort: tcpPort, Listen: "127.0.0.1", AllowPrivate: true,
		ExitVia: "192.0.2.1", ExitEmails: []string{twin.Email},
	}, []profile.Device{dev, twin})
	must(t, err)
	srv, err := xray.Start(srvCfg)
	must(t, err)
	t.Cleanup(func() { srv.Close() })

	p := profile.Profile{
		Host:      host,
		WireGuard: profile.WireGuardConf{Port: 51820, ServerPublicKey: "key", Address: []string{"10.8.0.2/32"}},
		Reality:   profile.RealityConf{Port: tcpPort, UUID: dev.UUID, PublicKey: realityPub, ShortID: shortID},
		Exit:      &profile.ExitConf{UUID: twin.UUID, HysteriaAuth: twin.HysteriaAuth, Username: twin.Email, AnyTLSPassword: "exit"},
	}
	via := func(p profile.Profile) (string, error) {
		socks := freeTCP(t)
		cfg, err := profile.ClientXray(p, profile.Reality, profile.ClientInbound{SocksPort: socks, Address: "127.0.0.1"})
		must(t, err)
		cli, err := xray.Start(cfg)
		must(t, err)
		defer cli.Close()
		var body string
		for range 4 {
			if body, err = tryVia(socks, "http://"+dest); err == nil {
				break
			}
		}
		return body, err
	}
	if body, err := via(p); err != nil || body != "hello through the tunnel" {
		t.Fatalf("own login: %q %v", body, err)
	}
	exit, ok := p.WithExit()
	if !ok {
		t.Fatal("no exit")
	}
	if body, err := via(exit); err == nil {
		t.Fatalf("the exit login didn't go to the exit: %q", body)
	}
}

func TestWithExit(t *testing.T) {
	p := profile.Profile{
		Host:        host,
		WireGuard:   profile.WireGuardConf{Port: 51820, ServerPublicKey: "key", Address: []string{"10.8.0.2/32"}, MTU: 1280},
		AmneziaWG:   &profile.AmneziaConf{Port: 51821},
		Reality:     profile.RealityConf{Port: 443, UUID: "own"},
		Hysteria2:   &profile.HysteriaConf{Port: 443, Auth: "own"},
		TrustTunnel: &profile.TrustTunnelConf{Port: 443, Username: "d1", Password: "pw"},
		AnyTLS:      &profile.AnyTLSConf{Port: 2083, Password: "own"},
		Mieru:       &profile.MieruConf{Port: 2096, Username: "d1", Password: "pw"},
		OpenVPN:     &profile.OpenVPNConf{Port: 1194, Cert: "c"},
		OpenConnect: &profile.OpenConnectConf{Server: "m.vpn.test"},
		IKEv2:       &profile.IKEv2Conf{Server: "v4.vpn.test"},
	}
	if _, ok := p.WithExit(); ok {
		t.Fatal("exit without an exit login")
	}
	p.Exit = &profile.ExitConf{UUID: "twin", HysteriaAuth: "twin", Username: "d1x", AnyTLSPassword: "twin"}
	q, ok := p.WithExit()
	if !ok {
		t.Fatal("no exit")
	}
	if q.Reality.UUID != "twin" || q.Hysteria2.Auth != "twin" || q.TrustTunnel.Username != "d1x" || q.Mieru.Username != "d1x" || q.AnyTLS.Password != "twin" {
		t.Fatalf("logins not swapped: %+v", q)
	}
	if p.Reality.UUID != "own" || p.Hysteria2.Auth != "own" || p.TrustTunnel.Username != "d1" {
		t.Fatal("WithExit changed the original")
	}
	for _, proto := range []string{profile.WireGuard, profile.AmneziaWG, profile.OpenVPN, profile.OpenConnect, profile.IKEv2} {
		if profile.Offered(q, proto) {
			t.Errorf("%s offered with the exit", proto)
		}
	}
	for _, proto := range []string{profile.Reality, profile.Hysteria2, profile.TrustTunnel, profile.AnyTLS, profile.Mieru} {
		if !profile.Offered(q, proto) {
			t.Errorf("%s not offered with the exit", proto)
		}
	}
	if q.WireGuard.MTU != 1280 || len(q.WireGuard.Address) != 1 {
		t.Fatal("the tunnel's addresses and MTU must stay")
	}
	b, _ := json.Marshal(p)
	var back profile.Profile
	must(t, json.Unmarshal(b, &back))
	if back.Exit == nil || back.Exit.Username != "d1x" {
		t.Fatalf("exit lost in JSON: %s", b)
	}
}
