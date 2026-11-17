package vpn

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

func TestOpenVPNPKI(t *testing.T) {
	dir := t.TempDir()
	newOVPN := func() *openvpn {
		o := &openvpn{dir: dir, host: "vpn.test", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if err := o.loadPKI(); err != nil {
			t.Fatal(err)
		}
		return o
	}
	o := newOVPN()
	d := store.Device{UUID: "6f1c2b9e-0000-4000-8000-000000000001", Name: "phone", PersonName: "Ann"}
	conf, err := o.clientConfig(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"remote vpn.test 1194", "verify-x509-name vpn.test name", "<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("ovpn lacks %q", want)
		}
	}
	section := func(conf, tag string) []byte {
		_, rest, _ := strings.Cut(conf, "<"+tag+">\n")
		body, _, _ := strings.Cut(rest, "</"+tag+">")
		return []byte(body)
	}
	b, _ := pem.Decode(section(conf, "cert"))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != d.UUID {
		t.Fatalf("CN %q", cert.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(section(conf, "ca"))
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(section(conf, "key"))
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.(*ecdsa.PrivateKey).PublicKey) {
		t.Fatal("key does not match certificate")
	}
	// A restart reloads the same CA and derives the same device key.
	again, err := newOVPN().clientConfig(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(section(again, "key")) != string(section(conf, "key")) || string(section(again, "ca")) != string(section(conf, "ca")) {
		t.Fatal("device key or CA changed after reload")
	}
	other, _ := o.clientConfig(store.Device{UUID: "another"})
	if string(section(other, "key")) == string(section(conf, "key")) {
		t.Fatal("two devices share a key")
	}
	if !strings.Contains(o.serverConfig(), "ccd-exclusive") {
		t.Fatal("server must only admit devices with a ccd file")
	}

	// A new domain gets a server certificate for it from the same CA.
	moved := &openvpn{dir: dir, host: "new.test", log: o.log}
	if err := moved.loadPKI(); err != nil {
		t.Fatal(err)
	}
	srv, _ := os.ReadFile(filepath.Join(dir, "server.pem"))
	sb, _ := pem.Decode(srv)
	srvCert, err := x509.ParseCertificate(sb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srvCert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "new.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	movedConf, _ := moved.clientConfig(d)
	if string(section(movedConf, "key")) != string(section(conf, "key")) || string(section(movedConf, "ca")) != string(section(conf, "ca")) {
		t.Fatal("device key or CA changed with the domain")
	}
}
