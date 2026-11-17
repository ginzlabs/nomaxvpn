package vpn

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// OpenConnect (the protocol of Cisco AnyConnect) runs in ocserv, a root service
// of its own (infra/host/ocserv.conf). nomax keeps ocserv's password file and
// certificate in StateDir/ocserv, forwards TLS for OCServer on 443 to it, and
// reaches occtl through nomax-occtl, a socket-activated helper that runs a
// fixed set of occtl commands. Devices log in with the IKEv2 credentials.
const (
	OCAddr     = "127.0.0.1:4443" // ocserv's TCP side, reached through 443; UDP 4443 (DTLS) is public
	OCDTLSPort = 4443
	OCSocket   = "/run/nomax-occtl.sock"
)

// OCServer is the name OpenConnect clients dial, or "" when the host is an
// address and TLS on 443 can't be told apart by name.
func OCServer(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return "m." + host
}

// OCSecret keeps ocserv hidden: deploy sets it as ocserv's camouflage secret,
// so a request without "?"+OCSecret as the first on its connection gets a 404,
// and the apps send it. Derived like the other hidden values.
func OCSecret(wgPrivateKey string) string {
	sum := sha256.Sum256([]byte("nomax ocserv\x00" + wgPrivateKey))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:20]
}

type openconnect struct {
	dir    string
	passwd string            // the password file as last written
	lines  map[string]string // device UUID -> passwd line, so each is hashed once
	users  map[string]bool
	cert   string
	seen   map[int]wgCounters // by ocserv session ID
}

// startOpenConnect returns nil when ocserv isn't installed (nomax-occtl absent).
func startOpenConnect(dir string) (*openconnect, error) {
	if _, err := os.Stat(OCSocket); err != nil {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	o := &openconnect{dir: dir, lines: map[string]string{}, users: map[string]bool{}, seen: map[int]wgCounters{}}
	if b, err := os.ReadFile(filepath.Join(dir, "passwd")); err == nil {
		o.passwd = string(b)
		for line := range strings.SplitSeq(o.passwd, "\n") {
			if u, _, ok := strings.Cut(line, ":"); ok {
				o.users[u] = true
			}
		}
	}
	return o, nil
}

// setUsers writes one login per device and disconnects the ones removed.
func (o *openconnect) setUsers(devices []store.Device, password func(store.Device) string, salt func(store.Device) string) error {
	want := map[string]bool{}
	lines := make([]string, 0, len(devices))
	keep := map[string]string{}
	for _, d := range devices {
		line, ok := o.lines[d.UUID]
		if !ok {
			line = d.Email() + ":*:" + sha512Crypt(password(d), salt(d))
		}
		keep[d.UUID] = line
		want[d.Email()] = true
		lines = append(lines, line)
	}
	o.lines = keep
	slices.Sort(lines)
	body := strings.Join(lines, "\n") + "\n"
	if body != o.passwd {
		if err := writeAtomic(filepath.Join(o.dir, "passwd"), body); err != nil {
			return err
		}
		o.passwd = body
	}
	var errs []error
	for u := range o.users {
		if !want[u] {
			if err := o.ctl("disconnect", u); err != nil {
				errs = append(errs, err)
			}
		}
	}
	o.users = want
	return errors.Join(errs...)
}

// setCert installs the certificate for OCServer and has ocserv reload it.
func (o *openconnect) setCert(certPEM, keyPEM string) error {
	if certPEM == o.cert {
		return nil
	}
	if err := writeAtomic(filepath.Join(o.dir, "key.pem"), keyPEM); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(o.dir, "cert.pem"), certPEM); err != nil {
		return err
	}
	if err := o.ctl("reload", ""); err != nil {
		return err
	}
	o.cert = certPEM
	return nil
}

// usage adds traffic since the last call per username, and disconnects
// sessions of users that are gone (removed while nomax was down).
func (o *openconnect) usage(add func(user string, rx, tx int64)) {
	out, err := o.call("users", "")
	if err != nil {
		return
	}
	var sessions []struct {
		ID       int
		Username string
		RX, TX   string
	}
	if json.Unmarshal(out, &sessions) != nil {
		return
	}
	live := map[int]wgCounters{}
	for _, s := range sessions {
		if !o.users[s.Username] {
			o.ctl("disconnect", s.Username)
			continue
		}
		rx, _ := strconv.ParseInt(s.RX, 10, 64)
		tx, _ := strconv.ParseInt(s.TX, 10, 64)
		cur := wgCounters{rx: rx, tx: tx}
		prev := o.seen[s.ID]
		if cur.rx < prev.rx || cur.tx < prev.tx {
			prev = wgCounters{}
		}
		live[s.ID] = cur
		add(s.Username, cur.rx-prev.rx, cur.tx-prev.tx)
	}
	o.seen = live
}

// ctl runs a command that answers "ok" on success.
func (o *openconnect) ctl(cmd, arg string) error {
	out, err := o.call(cmd, arg)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "ok" {
		return fmt.Errorf("ocserv: %s %s failed", cmd, arg)
	}
	return nil
}

func (o *openconnect) call(cmd, arg string) ([]byte, error) {
	c, err := net.DialTimeout("unix", OCSocket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ocserv: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	w := bufio.NewWriter(c)
	fmt.Fprintf(w, "%s %s\n", cmd, arg)
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return io.ReadAll(c)
}

// ocSalt is the device's crypt salt, derived so the password file stays the
// same between runs.
func (r *Runtime) ocSalt(d store.Device) string {
	m := hmac.New(sha256.New, r.ikeKey)
	m.Write([]byte("ocserv salt\x00" + d.UUID))
	sum := m.Sum(nil)
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = cryptAlphabet[sum[i]&0x3f]
	}
	return string(salt)
}

func writeAtomic(path, body string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
