package vpn

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// OpenVPN runs as a child process with its own CA. Each device's certificate
// is named after its UUID; ccd-exclusive only admits names that have a file in
// ccd/, so removing the file (and killing the session) revokes the device.
const (
	OVPNPort      = 1194
	OVPNInterface = "ovpn0"
)

type openvpn struct {
	dir, sock, host string
	caPEM, tlsCrypt string
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	seed            []byte // derives device keys, so none are stored
	log             *slog.Logger

	mu    sync.Mutex
	ccd   map[string]string
	certs map[string]profile.OpenVPNConf // by device UUID, so profiles stay the same between fetches
	seen  map[string]wgCounters
	stop  chan struct{}
	done  chan struct{}
}

func startOpenVPN(dir, runDir, host string, log *slog.Logger) (*openvpn, error) {
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	o := &openvpn{dir: dir, sock: filepath.Join(runDir, "openvpn.sock"), host: host, log: log,
		ccd: map[string]string{}, certs: map[string]profile.OpenVPNConf{}, seen: map[string]wgCounters{}, stop: make(chan struct{}), done: make(chan struct{})}
	if err := os.MkdirAll(filepath.Join(dir, "ccd"), 0o700); err != nil {
		return nil, err
	}
	if err := o.loadPKI(); err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}
	conf := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(conf, []byte(o.serverConfig()), 0o600); err != nil {
		return nil, err
	}
	go o.supervise(bin, conf)
	return o, nil
}

func (o *openvpn) serverConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, `port %d
proto udp6
dev %s
dev-type tun
disable-dco
topology subnet
server 10.8.2.0 255.255.255.0
server-ipv6 fd08:2::/64
push "redirect-gateway def1 ipv6 bypass-dhcp"
`, OVPNPort, OVPNInterface)
	for _, d := range profile.DNS {
		if strings.Contains(d, ":") {
			fmt.Fprintf(&b, "push \"dhcp-option DNS6 %s\"\n", d)
		} else {
			fmt.Fprintf(&b, "push \"dhcp-option DNS %s\"\n", d)
		}
	}
	fmt.Fprintf(&b, `ca ca.pem
cert server.pem
key server.key
dh none
tls-crypt tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verify-client-cert require
client-config-dir ccd
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
management %s unix
verb 1
mute-replay-warnings
`, o.sock)
	return b.String()
}

func (o *openvpn) supervise(bin, conf string) {
	defer close(o.done)
	for {
		cmd := exec.Command(bin, "--config", conf)
		cmd.Dir = o.dir
		out, _ := cmd.StdoutPipe()
		cmd.Stderr = cmd.Stdout
		started := time.Now()
		if err := cmd.Start(); err != nil {
			o.log.Error("openvpn", "err", err)
		} else {
			o.log.Info("openvpn up", "port", OVPNPort)
			exited := make(chan error, 1)
			go func() {
				sc := bufio.NewScanner(out)
				for sc.Scan() {
					o.log.Info("openvpn: " + sc.Text())
				}
				exited <- cmd.Wait()
			}()
			select {
			case <-o.stop:
				cmd.Process.Signal(os.Interrupt)
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
					cmd.Process.Kill()
				}
				return
			case err := <-exited:
				o.log.Warn("openvpn exited", "err", err)
			}
		}
		wait := 2 * time.Second
		if time.Since(started) < 10*time.Second {
			wait = 30 * time.Second
		}
		select {
		case <-o.stop:
			return
		case <-time.After(wait):
		}
	}
}

func (o *openvpn) close() {
	close(o.stop)
	<-o.done
}

// setClients writes one ccd file per device (pinning its addresses) and
// removes the rest, disconnecting them.
func (o *openvpn) setClients(devices []store.Device) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	want := map[string]string{}
	for _, d := range devices {
		want[d.UUID] = fmt.Sprintf("ifconfig-push 10.8.2.%d 255.255.255.0\nifconfig-ipv6-push fd08:2::%x/64 fd08:2::1\n", d.WGIndex, d.WGIndex)
	}
	if len(o.ccd) == 0 {
		entries, _ := os.ReadDir(filepath.Join(o.dir, "ccd"))
		for _, e := range entries {
			o.ccd[e.Name()] = ""
		}
	}
	var errs []error
	for name, body := range want {
		if o.ccd[name] == body {
			continue
		}
		if err := os.WriteFile(filepath.Join(o.dir, "ccd", name), []byte(body), 0o600); err != nil {
			errs = append(errs, err)
			continue
		}
		o.ccd[name] = body
	}
	for name := range o.ccd {
		if _, ok := want[name]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(o.dir, "ccd", name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		delete(o.ccd, name)
		o.manage("kill " + name)
	}
	return errors.Join(errs...)
}

// manage sends one command over the management socket and returns the reply lines.
func (o *openvpn) manage(command string) ([]string, error) {
	c, err := net.DialTimeout("unix", o.sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil {
		return nil, err
	}
	fmt.Fprintf(c, "%s\n", command)
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return lines, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, ">"):
		case line == "END", strings.HasPrefix(line, "SUCCESS:"):
			fmt.Fprint(c, "quit\n")
			return lines, nil
		case strings.HasPrefix(line, "ERROR:"):
			return lines, errors.New(line)
		default:
			lines = append(lines, line)
		}
	}
}

// usage adds traffic since the last call per certificate name (device UUID).
func (o *openvpn) usage(add func(uuid string, rx, tx int64)) {
	lines, err := o.manage("status 3")
	if err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	live := map[string]wgCounters{}
	for _, l := range lines {
		f := strings.Split(l, "\t")
		// CLIENT_LIST CN Real Virtual Virtual6 BytesReceived BytesSent Since SinceT Username ClientID ...
		if len(f) < 11 || f[0] != "CLIENT_LIST" {
			continue
		}
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		cur := wgCounters{rx: rx, tx: tx}
		prev := o.seen[f[10]]
		if cur.rx < prev.rx || cur.tx < prev.tx {
			prev = wgCounters{}
		}
		live[f[10]] = cur
		add(f[1], cur.rx-prev.rx, cur.tx-prev.tx)
	}
	o.seen = live
}

// clientCreds is the device's certificate and key, with the CA and tls-crypt key.
func (o *openvpn) clientCreds(d store.Device) (profile.OpenVPNConf, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if c, ok := o.certs[d.UUID]; ok {
		return c, nil
	}
	key, err := o.deviceKey(d.UUID)
	if err != nil {
		return profile.OpenVPNConf{}, err
	}
	certPEM, err := o.issue(pkix.Name{CommonName: d.UUID}, &key.PublicKey, x509.ExtKeyUsageClientAuth, 10*365*24*time.Hour)
	if err != nil {
		return profile.OpenVPNConf{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return profile.OpenVPNConf{}, err
	}
	c := profile.OpenVPNConf{Port: OVPNPort, CA: o.caPEM, Cert: certPEM,
		Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), TLSCrypt: o.tlsCrypt}
	if o.certs == nil {
		o.certs = map[string]profile.OpenVPNConf{}
	}
	o.certs[d.UUID] = c
	return c, nil
}

// clientConfig is a complete .ovpn for one device.
func (o *openvpn) clientConfig(d store.Device) (string, error) {
	c, err := o.clientCreds(d)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`# NoMax: %s (%s)
client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name %s name
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tls-version-min 1.2
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
<tls-crypt>
%s</tls-crypt>
`, d.Name, d.PersonName, o.host, OVPNPort, o.host, c.CA, c.Cert, c.Key, c.TLSCrypt), nil
}

// deviceKey derives a P-256 key from the device UUID.
func (o *openvpn) deviceKey(uuid string) (*ecdsa.PrivateKey, error) {
	for i := byte(0); i < 16; i++ {
		m := hmac.New(sha256.New, o.seed)
		m.Write([]byte{i})
		m.Write([]byte(uuid))
		k, err := ecdh.P256().NewPrivateKey(m.Sum(nil))
		if err != nil {
			continue
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		pk, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		return pk.(*ecdsa.PrivateKey), nil
	}
	return nil, errors.New("openvpn: no key")
}

func (o *openvpn) issue(name pkix.Name, pub *ecdsa.PublicKey, eku x509.ExtKeyUsage, valid time.Duration) (string, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(valid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	if eku == x509.ExtKeyUsageServerAuth {
		tmpl.DNSNames = []string{name.CommonName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.caCert, pub, o.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// loadPKI reads the CA, server certificate and tls-crypt key, creating them on first run.
func (o *openvpn) loadPKI() error {
	path := func(n string) string { return filepath.Join(o.dir, n) }
	caKeyPEM, err := os.ReadFile(path("ca.key"))
	if errors.Is(err, os.ErrNotExist) {
		if err := o.createPKI(); err != nil {
			return err
		}
		caKeyPEM, err = os.ReadFile(path("ca.key"))
	}
	if err != nil {
		return err
	}
	b, _ := pem.Decode(caKeyPEM)
	if b == nil {
		return errors.New("bad ca.key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	if o.caKey, ok = k.(*ecdsa.PrivateKey); !ok {
		return errors.New("ca.key is not ECDSA")
	}
	seed := sha256.Sum256(append([]byte("nomax openvpn\x00"), b.Bytes...))
	o.seed = seed[:]
	caPEM, err := os.ReadFile(path("ca.pem"))
	if err != nil {
		return err
	}
	if b, _ = pem.Decode(caPEM); b == nil {
		return errors.New("bad ca.pem")
	}
	if o.caCert, err = x509.ParseCertificate(b.Bytes); err != nil {
		return err
	}
	o.caPEM = string(caPEM)
	tc, err := os.ReadFile(path("tls-crypt.key"))
	if err != nil {
		return err
	}
	o.tlsCrypt = string(tc)
	return o.nameServer()
}

// nameServer reissues the server certificate when the domain has changed
// (clients check it against the host), keeping the CA and devices' certificates.
func (o *openvpn) nameServer() error {
	path := func(n string) string { return filepath.Join(o.dir, n) }
	srvPEM, err := os.ReadFile(path("server.pem"))
	if err != nil {
		return err
	}
	b, _ := pem.Decode(srvPEM)
	if b == nil {
		return errors.New("bad server.pem")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if cert.VerifyHostname(o.host) == nil {
		return nil
	}
	keyPEM, err := os.ReadFile(path("server.key"))
	if err != nil {
		return err
	}
	if b, _ = pem.Decode(keyPEM); b == nil {
		return errors.New("bad server.key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("server.key is not ECDSA")
	}
	issued, err := o.issue(pkix.Name{CommonName: o.host}, &key.PublicKey, x509.ExtKeyUsageServerAuth, 30*365*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path("server.pem"), []byte(issued), 0o600); err != nil {
		return err
	}
	o.log.Info("openvpn: reissued the server certificate", "host", o.host)
	return nil
}

func (o *openvpn) createPKI() error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NoMax OpenVPN CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if o.caCert, err = x509.ParseCertificate(caDER); err != nil {
		return err
	}
	o.caKey = caKey
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvPEM, err := o.issue(pkix.Name{CommonName: o.host}, &srvKey.PublicKey, x509.ExtKeyUsageServerAuth, 30*365*24*time.Hour)
	if err != nil {
		return err
	}
	caKeyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	static := make([]byte, 256)
	rand.Read(static)
	var tc strings.Builder
	tc.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(static); i += 16 {
		tc.WriteString(hex.EncodeToString(static[i:i+16]) + "\n")
	}
	tc.WriteString("-----END OpenVPN Static key V1-----\n")
	files := []struct {
		name string
		data []byte
	}{
		{"ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})},
		{"server.pem", []byte(srvPEM)},
		{"server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})},
		{"tls-crypt.key", []byte(tc.String())},
		{"ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})}, // last: its presence means done
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(o.dir, f.name), f.data, 0o600); err != nil {
			return err
		}
	}
	o.log.Info("openvpn: created CA and server certificate")
	return nil
}
