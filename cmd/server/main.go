// Command nomax is the whole server: Xray (Reality, Hysteria2), WireGuard peer
// management, the device API and the admin panel.
//
//	nomax             serve (configured by environment, see infra/host/nomax.service)
//	nomax admin-code  read a new admin code from stdin; signs everyone out and clears lockouts
//	                  (-if-unset: only when none is set yet)
//	nomax version
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/panel"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"github.com/ginzlabs/nomaxvpn/internal/vpn"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme/autocert"
)

var version = "dev"

const panelAddr = "127.0.0.1:8443"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(logger)
	case "admin-code":
		err = adminCode()
	case "reports":
		err = reports(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func stateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return d
	}
	return "/var/lib/nomax"
}

func openStore() (*store.Store, error) {
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(stateDir(), "nomax.db"))
}

func adminCode() error {
	ifUnset := len(os.Args) > 2 && os.Args[2] == "-if-unset"
	if ifUnset {
		st, err := openStore()
		if err != nil {
			return err
		}
		h, err := st.Setting(panel.AdminHashKey)
		st.Close()
		if err != nil {
			return err
		}
		if h != "" {
			io.Copy(io.Discard, os.Stdin)
			fmt.Println("admin code already set")
			return nil
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	code := strings.TrimSpace(line)
	if len(code) < 12 {
		return errors.New("admin code must be at least 12 characters")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SetSetting(panel.AdminHashKey, panel.HashCode(code)); err != nil {
		return err
	}
	if err := st.ResetAdmin(); err != nil {
		return err
	}
	fmt.Println("admin code updated")
	return nil
}

func env(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func serve(logger *slog.Logger) error {
	domain := env("DOMAIN")
	if domain == "" {
		return errors.New("DOMAIN is required")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	// Apple's reviewers (an iPhone and a Mac) and CI's live tests, which can overlap.
	if err := st.EnsureReviewer("App Review", env("REVIEW_CODE"), 5); err != nil {
		return err
	}

	rt, err := vpn.New(vpn.Config{
		WGPrivateKey: env("WG_PRIVATE_KEY"),
		Server: profile.Server{
			Host:              domain,
			RealityPrivateKey: env("REALITY_PRIVATE_KEY"),
			RealityShortID:    env("REALITY_SHORT_ID"),
			RealityTarget:     panelAddr,
			TCPPort:           443,
			UDPPort:           443,
			MuxPort:           vpn.RealityMuxPort,
			ObfsPort:          vpn.ObfsPort,
			MasqueradeURL:     "https://" + panelAddr,
			CloudflareAddr:    vpn.CloudflareAddr,
		},
		StateDir:   stateDir(),
		RunDir:     os.Getenv("RUNTIME_DIRECTORY"),
		AnyTLSPort: vpn.AnyTLSPort,
		MieruPort:  vpn.MieruPort,
		Relays:     strings.FieldsFunc(env("RELAYS"), func(r rune) bool { return r == ',' || r == ' ' }),
		MovedTo:    env("MOVED_TO"),
	}, logger)
	if err != nil {
		return err
	}
	defer rt.Close()

	names := certNames(domain)
	acme := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(names...),
		Cache:      autocert.DirCache(filepath.Join(stateDir(), "acme")),
	}
	for _, name := range names {
		if c, k, ok := cachedCert(acme, certKey(domain, name)); ok {
			setCert(rt, domain, name, c, k)
		}
	}

	kick := make(chan struct{}, 1)
	kickFn := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	p := panel.New(panel.Config{
		Host:          domain,
		AdminPath:     env("ADMIN_PATH"),
		APIPath:       env("API_PATH"),
		FilesPath:     env("FILES_PATH"),
		PrivacyPath:   env("PRIVACY_PATH"),
		TestFlightURL: env("TESTFLIGHT_URL"),
		Version:       version,
		APKPath:       filepath.Join(stateDir(), "public", "nomax.apk"),
		WindowsPath:   filepath.Join(stateDir(), "public", "nomax-setup.exe"),
	}, st, rt, kickFn, logger)

	quiet := log.New(io.Discard, "", 0)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName == "" {
				h.ServerName = domain
			}
			return acme.GetCertificate(h)
		},
	}
	panelSrv := &http.Server{
		Handler:           rt.Front(p.Handler()),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          quiet,
	}
	raw, err := net.Listen("tcp", panelAddr)
	if err != nil {
		return err
	}
	var panelLn net.Listener = &proxyproto.Listener{Listener: raw, ReadHeaderTimeout: 5 * time.Second}
	if oc := vpn.OCServer(domain); oc != "" {
		panelLn = routeSNI(panelLn, oc, vpn.OCAddr, logger)
	}
	httpSrv := &http.Server{
		Addr:              ":80",
		Handler:           acme.HTTPHandler(nil),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          quiet,
	}

	errc := make(chan error, 2)
	go func() { errc <- panelSrv.ServeTLS(panelLn, "", "") }()
	go func() { errc <- httpSrv.ListenAndServe() }()

	stop := make(chan struct{})
	go rt.Loop(st, kick, 30*time.Second, stop)
	go certLoop(acme, domain, rt, kickFn, logger, stop)
	go func() {
		for {
			st.Prune()
			select {
			case <-stop:
				return
			case <-time.After(time.Hour):
			}
		}
	}()
	logger.Info("nomax started", "version", version, "domain", domain)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		logger.Info("stopping", "signal", s.String())
	case err := <-errc:
		logger.Error("listener", "err", err)
	}
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	panelSrv.Shutdown(ctx)
	httpSrv.Shutdown(ctx)
	return nil
}

// certNames are the names with a Let's Encrypt certificate: the domain, the
// IPv4-only name IKEv2 clients dial, the name of OpenConnect's server, and the
// website's name behind Cloudflare.
func certNames(domain string) []string {
	names := []string{domain}
	if ike := vpn.IKEServer(domain); ike != domain {
		names = append(names, ike)
	}
	if oc := vpn.OCServer(domain); oc != "" {
		names = append(names, oc)
	}
	// Cloudflare's name gets its certificate over HTTP, as Cloudflare doesn't
	// pass tls-alpn-01 through.
	if web := vpn.CloudflareServer(domain); web != "" {
		names = append(names, web)
	}
	return names
}

// certHello asks autocert for the kind of certificate each name needs. Android's
// IKEv2 client only verifies RSA signatures, so the IKEv2 name gets an RSA one.
func certHello(domain, name string) *tls.ClientHelloInfo {
	suite := tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	if name == vpn.IKEServer(domain) && name != domain {
		suite = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	}
	return &tls.ClientHelloInfo{ServerName: name, CipherSuites: []uint16{suite}}
}

// certKey is autocert's cache key for the certificate certHello asks for.
func certKey(domain, name string) string {
	if name == vpn.IKEServer(domain) && name != domain {
		return name + "+rsa"
	}
	return name
}

func setCert(rt *vpn.Runtime, domain, name, certPEM, keyPEM string) {
	switch name {
	case domain:
		rt.SetCert(certPEM, keyPEM)
	case vpn.IKEServer(domain):
		rt.SetIKECert(certPEM, keyPEM)
	case vpn.OCServer(domain):
		rt.SetOCCert(certPEM, keyPEM)
	}
}

// certLoop obtains and renews the Let's Encrypt certificates and hands them to
// Hysteria2, IKEv2 and ocserv whenever they change.
func certLoop(acme *autocert.Manager, domain string, rt *vpn.Runtime, kick func(), logger *slog.Logger, stop <-chan struct{}) {
	current := map[string]string{}
	for {
		wait := 12 * time.Hour
		for _, name := range certNames(domain) {
			if _, err := acme.GetCertificate(certHello(domain, name)); err != nil {
				logger.Warn("certificate", "name", name, "err", err)
				wait = 5 * time.Minute
			} else if c, k, ok := cachedCert(acme, certKey(domain, name)); ok && c != current[name] {
				current[name] = c
				setCert(rt, domain, name, c, k)
				kick()
				logger.Info("certificate ready", "name", name)
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}

// cachedCert splits autocert's cache entry (key then chain, PEM) for Xray.
func cachedCert(acme *autocert.Manager, domain string) (certPEM, keyPEM string, ok bool) {
	data, err := acme.Cache.Get(context.Background(), domain)
	if err != nil {
		return "", "", false
	}
	var certs, key []byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			key = pem.EncodeToMemory(b)
		} else if b.Type == "CERTIFICATE" {
			certs = append(certs, pem.EncodeToMemory(b)...)
		}
	}
	if len(certs) == 0 || len(key) == 0 {
		return "", "", false
	}
	return string(certs), string(key), true
}
