package profile_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/tlsutil"
	"github.com/ginzlabs/nomaxvpn/internal/vpn"
	"github.com/ginzlabs/nomaxvpn/internal/xray"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/net/proxy"
)

const host = "vpn.test"

// TestLoopback runs a real server and client Xray in-process and pushes HTTP
// through Reality, Hysteria2 and Cloudflare's route, plus checks that a plain
// TLS visitor on the Reality port lands on the decoy site, and one on
// Cloudflare's name, the website.
func TestLoopback(t *testing.T) {
	dest := serveHTTP(t, "hello through the tunnel")

	certPEM, keyPEM, err := tlsutil.SelfSigned(host)
	must(t, err)
	pin, err := tlsutil.LeafPin(certPEM)
	must(t, err)
	decoy := serveDecoy(t, certPEM, keyPEM)

	tcpPort, udpPort, muxPort, obfsPort, cfPort := freeTCP(t), freeUDP(t), freeTCP(t), freeUDP(t), freeTCP(t)
	obfsPassword := profile.RandomToken(16)
	cfAddr, cfPath := fmt.Sprintf("127.0.0.1:%d", cfPort), "/"+profile.RandomHex(10)
	front, frontPin := serveCloudflare(t, cfPath, cfAddr)
	realityKey := profile.NewRealityKey()
	realityPub, err := profile.RealityPublic(realityKey)
	must(t, err)
	shortID := profile.RandomHex(8)
	dev := profile.Device{Email: "d1", UUID: "6a3c9f8e-5b2d-4c1a-9e7f-0d8b2a4c6e1f", HysteriaAuth: profile.RandomToken(24)}

	srvCfg, err := profile.ServerXray(profile.Server{
		Host:              host,
		RealityPrivateKey: realityKey,
		RealityShortID:    shortID,
		RealityTarget:     decoy,
		TCPPort:           tcpPort,
		UDPPort:           udpPort,
		MuxPort:           muxPort,
		ObfsPort:          obfsPort,
		ObfsPassword:      obfsPassword,
		CertPEM:           certPEM,
		KeyPEM:            keyPEM,
		MasqueradeURL:     "https://" + decoy,
		CloudflareAddr:    cfAddr,
		CloudflarePath:    cfPath,
		Listen:            "127.0.0.1",
		AllowPrivate:      true,
	}, []profile.Device{dev})
	must(t, err)
	if os.Getenv("XRAY_DEBUG") != "" {
		srvCfg = bytes.Replace(srvCfg, []byte(`"warning"`), []byte(`"debug"`), 1)
	}
	srv, err := xray.Start(srvCfg)
	must(t, err)
	t.Cleanup(func() { srv.Close() })

	p := profile.Profile{
		Host:    host,
		Reality: profile.RealityConf{Port: tcpPort, UUID: dev.UUID, PublicKey: realityPub, ShortID: shortID, MuxPort: muxPort},
		Hysteria2: &profile.HysteriaConf{Port: udpPort, Auth: dev.HysteriaAuth, PinSHA256: pin, Obfs: &profile.HysteriaObfs{
			Port: obfsPort, Password: obfsPassword, HopPorts: fmt.Sprintf("%d-%d", obfsPort, obfsPort),
		}},
		Cloudflare: &profile.CloudflareConf{Host: cfHost, Port: front, Path: cfPath, Addresses: []string{"127.0.0.1"}, PinSHA256: frontPin},
	}
	setCheckURL(t)
	for _, proto := range []string{profile.Reality, profile.RealityMux, profile.Hysteria2, profile.Hysteria2Obfs, profile.Cloudflare} {
		t.Run(proto, func(t *testing.T) {
			socks := freeTCP(t)
			cfg, err := profile.ClientXray(p, proto, profile.ClientInbound{SocksPort: socks, Address: "127.0.0.1"})
			must(t, err)
			if os.Getenv("XRAY_DEBUG") != "" {
				cfg = bytes.Replace(cfg, []byte(`"warning"`), []byte(`"debug"`), 1)
			}
			cli, err := xray.Start(cfg)
			must(t, err)
			defer cli.Close()
			got := getVia(t, socks, "http://"+dest)
			if got != "hello through the tunnel" {
				t.Fatalf("got %q", got)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if res, err := cli.Check(ctx, nil); err != nil || res.Bytes != 256<<10 {
				t.Fatalf("check: %+v %v", res, err)
			}
		})
	}

	t.Run("wrong-salamander", func(t *testing.T) {
		bad := p
		obfs := *p.Hysteria2.Obfs
		obfs.Password = "not the password"
		hy := *p.Hysteria2
		hy.Obfs = &obfs
		bad.Hysteria2 = &hy
		socks := freeTCP(t)
		cfg, err := profile.ClientXray(bad, profile.Hysteria2Obfs, profile.ClientInbound{SocksPort: socks, Address: "127.0.0.1"})
		must(t, err)
		cli, err := xray.Start(cfg)
		must(t, err)
		defer cli.Close()
		if _, err := tryVia(socks, "http://"+dest); err == nil {
			t.Fatal("a wrong salamander password got through")
		}
	})

	t.Run("wrong-credentials", func(t *testing.T) {
		bad := p
		bad.Reality.UUID = "00000000-0000-4000-8000-000000000000"
		socks := freeTCP(t)
		cfg, err := profile.ClientXray(bad, profile.Reality, profile.ClientInbound{SocksPort: socks, Address: "127.0.0.1"})
		must(t, err)
		cli, err := xray.Start(cfg)
		must(t, err)
		defer cli.Close()
		if _, err := tryVia(socks, "http://"+dest); err == nil {
			t.Fatal("unknown UUID got through")
		}
	})

	t.Run("decoy", func(t *testing.T) {
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true},
		}}
		resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d/", tcpPort))
		must(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "decoy from 127.0.0.1" {
			t.Fatalf("decoy got %q", body)
		}
	})

	t.Run("cloudflare-website", func(t *testing.T) {
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: cfHost, InsecureSkipVerify: true},
		}}
		for _, path := range []string{"/", cfPath} {
			resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d%s", front, path))
			must(t, err)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "the website" {
				t.Fatalf("%s got %q", path, body)
			}
		}
	})

	traffic := srv.TakeTraffic()
	if traffic["d1"].Down == 0 {
		t.Fatalf("no downlink counted for d1: %+v", traffic)
	}
}

func TestClientConfigsParse(t *testing.T) {
	p := profile.Profile{
		Host:      host,
		Reality:   profile.RealityConf{Port: 443, UUID: "6a3c9f8e-5b2d-4c1a-9e7f-0d8b2a4c6e1f", PublicKey: "x", ShortID: "ab"},
		Hysteria2: &profile.HysteriaConf{Port: 443, Auth: "a"},
	}
	for _, proto := range []string{profile.Reality, profile.Hysteria2} {
		cfg, err := profile.ClientXray(p, proto, profile.ClientInbound{TunMTU: 1400})
		must(t, err)
		var m map[string]any
		must(t, json.Unmarshal(cfg, &m))
	}
	if _, err := profile.ClientXray(p, profile.WireGuard, profile.ClientInbound{TunMTU: 1400}); err == nil {
		t.Fatal("wireguard through xray needs the device key")
	}
	if _, err := profile.ClientXray(p, profile.OpenVPN, profile.ClientInbound{TunMTU: 1400}); err == nil {
		t.Fatal("openvpn is not an Xray protocol")
	}
}

func TestWireGuardUAPI(t *testing.T) {
	srv := profile.NewWireGuardKey()
	pub, err := profile.WireGuardPublic(srv)
	must(t, err)
	p := profile.Profile{WireGuard: profile.WireGuardConf{Port: 51820, ServerPublicKey: pub}}
	uapi, err := profile.WireGuardUAPI(p, profile.WireGuard, profile.NewWireGuardKey(), "2001:db8::1")
	must(t, err)
	if !strings.Contains(uapi, "endpoint=[2001:db8::1]:51820\n") || strings.Contains(uapi, "jc=") {
		t.Fatalf("wireguard uapi: %q", uapi)
	}
	if _, err := profile.WireGuardUAPI(p, profile.AmneziaWG, profile.NewWireGuardKey(), "192.0.2.1"); err == nil {
		t.Fatal("amneziawg without server params should fail")
	}
}

func serveHTTP(t *testing.T, body string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	})}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

// setCheckURL points the tunnel check at a local 256 KB download.
func setCheckURL(t *testing.T) {
	body := strings.Repeat("x", 256<<10)
	old := xray.CheckURL
	xray.CheckURL = "http://" + serveHTTP(t, body) + "/"
	t.Cleanup(func() { xray.CheckURL = old })
}

const cfHost = "web." + host

// serveCloudflare stands in for Cloudflare and the website: TLS for cfHost,
// with WebSocket upgrades on path going to Xray at addr. It returns its port
// and the certificate's pin.
func serveCloudflare(t *testing.T, path, addr string) (int, string) {
	certPEM, keyPEM, err := tlsutil.SelfSigned(cfHost)
	must(t, err)
	pin, err := tlsutil.LeafPin(certPEM)
	must(t, err)
	pair, err := tlsutil.Pair(certPEM, keyPEM)
	must(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the website") })
	s := &http.Server{
		Handler:   vpn.CloudflareFront(site, path, addr),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2", "http/1.1"}},
	}
	go s.ServeTLS(ln, "", "")
	t.Cleanup(func() { s.Close() })
	return ln.Addr().(*net.TCPAddr).Port, pin
}

// serveDecoy is the Reality target: TLS behind PROXY protocol, like the panel.
func serveDecoy(t *testing.T, certPEM, keyPEM string) string {
	pair, err := tlsutil.Pair(certPEM, keyPEM)
	must(t, err)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ln := &proxyproto.Listener{Listener: raw}
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h, _, _ := net.SplitHostPort(r.RemoteAddr)
			io.WriteString(w, "decoy from "+h)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}},
	}
	go s.ServeTLS(ln, "", "")
	t.Cleanup(func() { s.Close() })
	return raw.Addr().String()
}

func getVia(t *testing.T, socksPort int, url string) string {
	t.Helper()
	var last error
	for range 20 {
		body, err := tryVia(socksPort, url)
		if err == nil {
			return body
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal(last)
	return ""
}

func tryVia(socksPort int, url string) (string, error) {
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.(proxy.ContextDialer).DialContext(ctx, network, addr)
		},
	}}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func freeTCP(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDP(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(t, err)
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
