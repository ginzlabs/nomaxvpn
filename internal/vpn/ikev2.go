package vpn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"github.com/strongswan/govici/vici"
)

// IKEv2 runs in strongSwan (charon-systemd). nomax configures it entirely over
// the VICI socket: a connection per server name (the domain, and the IPv4-only
// name clients dial), two address pools, the Let's Encrypt certificates and one
// EAP-MSCHAPv2 secret per device. strongSwan forgets all
// of it on restart, so every Apply checks the connection is still there.
const (
	ViciSocket = "/run/charon.vici"
	ikeConn    = "nomax"
	ikeConnV4  = "nomax-v4"
	IKEv2Pool4 = "10.8.1.0/24"
	IKEv2Pool6 = "fd08:1::/112"
)

var (
	ikeProposals = []string{"aes256gcm16-prfsha384-ecp384", "aes256gcm16-prfsha256-ecp256", "aes256-sha256-modp2048", "default"}
	espProposals = []string{"aes256gcm16-ecp384", "aes256gcm16-ecp256", "aes256gcm16", "aes256-sha256-modp2048", "aes256-sha256", "default"}
)

type ikev2 struct {
	sess    *vici.Session
	cert    string            // PEM chains loaded into charon
	secrets map[string]string // EAP identity -> password
	seen    map[string]wgCounters
}

// ikePassword is the device's EAP password, derived so nothing new is stored.
func (r *Runtime) ikePassword(d store.Device) string {
	m := hmac.New(sha256.New, r.ikeKey)
	m.Write([]byte(d.UUID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))[:24]
}

func (i *ikev2) call(cmd string, msg map[string]any) (*vici.Message, error) {
	var in *vici.Message
	if msg != nil {
		var err error
		if in, err = vici.MarshalMessage(msg); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := i.sess.Call(ctx, cmd, in)
	if err != nil {
		return nil, fmt.Errorf("ikev2: %s: %w", cmd, err)
	}
	return out, nil
}

func (i *ikev2) stream(cmd, event string, msg map[string]any) ([]*vici.Message, error) {
	in, err := vici.MarshalMessage(msg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out []*vici.Message
	for m, err := range i.sess.CallStreaming(ctx, cmd, event, in) {
		if err != nil {
			return nil, fmt.Errorf("ikev2: %s: %w", cmd, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// applyIKEv2 loads the connection and certificate when they are missing or
// changed, then syncs one secret per device. Removed devices are disconnected.
func (r *Runtime) applyIKEv2(devices []store.Device) error {
	if r.cert.cert == "" {
		return nil
	}
	if r.ike == nil {
		sess, err := vici.NewSession(vici.WithSocketPath(ViciSocket))
		if err != nil {
			return fmt.Errorf("ikev2: %w", err)
		}
		r.ike = &ikev2{sess: sess, secrets: map[string]string{}, seen: map[string]wgCounters{}}
	}
	err := r.syncIKEv2(devices)
	if err != nil {
		r.ike.sess.Close()
		r.ike = nil
	}
	return err
}

func (r *Runtime) syncIKEv2(devices []store.Device) error {
	i := r.ike
	names := r.ikeConns()
	loaded := 0
	for _, name := range names {
		conns, err := i.stream("list-conns", "list-conn", map[string]any{"ike": name})
		if err != nil {
			return err
		}
		for _, m := range conns {
			if m.Get(name) != nil {
				loaded++
			}
		}
	}
	if certs := r.cert.cert + r.ikeCert.cert; loaded < len(names) || i.cert != certs {
		if err := r.loadIKEv2(); err != nil {
			i.cert = ""
			return err
		}
		i.cert, i.secrets = certs, map[string]string{}
		r.log.Info("ikev2 loaded", "pool", IKEv2Pool4)
	}

	want := map[string]string{}
	for _, d := range devices {
		want[d.Email()] = r.ikePassword(d)
	}
	for id, pw := range want {
		if i.secrets[id] == pw {
			continue
		}
		if _, err := i.call("load-shared", map[string]any{"id": id, "type": "EAP", "data": pw, "owners": []string{id}}); err != nil {
			return err
		}
		i.secrets[id] = pw
	}
	var gone []string
	for id := range i.secrets {
		if _, ok := want[id]; !ok {
			if _, err := i.call("unload-shared", map[string]any{"id": id}); err != nil {
				return err
			}
			delete(i.secrets, id)
			gone = append(gone, id)
		}
	}
	if len(gone) > 0 {
		return i.terminate(gone)
	}
	return nil
}

// ikeConns names the connections loaded: the domain's, and the IPv4-only name's once it has a certificate.
func (r *Runtime) ikeConns() []string {
	if r.ikeCert.cert == "" {
		return []string{ikeConn}
	}
	return []string{ikeConn, ikeConnV4}
}

func (r *Runtime) loadIKEv2() error {
	i := r.ike
	if _, err := i.call("clear-creds", nil); err != nil {
		return err
	}
	leaf, err := i.loadCreds(r.cert.cert, r.cert.key)
	if err != nil {
		return err
	}
	pools := map[string]any{
		"nomax4": map[string]any{"addrs": IKEv2Pool4, "dns": profile.DNS},
		"nomax6": map[string]any{"addrs": IKEv2Pool6},
	}
	if _, err := i.call("load-pool", pools); err != nil {
		return err
	}
	if err := i.loadConn(ikeConn, r.cfg.Server.Host, leaf); err != nil {
		return err
	}
	if r.ikeCert.cert == "" {
		return nil
	}
	leaf, err = i.loadCreds(r.ikeCert.cert, r.ikeCert.key)
	if err != nil {
		return err
	}
	return i.loadConn(ikeConnV4, IKEServer(r.cfg.Server.Host), leaf)
}

// loadCreds loads a key and its chain, and returns the leaf certificate.
func (i *ikev2) loadCreds(chain, key string) (string, error) {
	var certs []string
	rest := []byte(chain)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		certs = append(certs, string(pem.EncodeToMemory(b)))
	}
	if len(certs) == 0 {
		return "", fmt.Errorf("ikev2: no certificate")
	}
	if _, err := i.call("load-key", map[string]any{"type": "any", "data": key}); err != nil {
		return "", err
	}
	// The intermediates let charon send the whole chain; clients only trust the root.
	for n, c := range certs {
		flag := "NONE"
		if n > 0 {
			flag = "CA"
		}
		if _, err := i.call("load-cert", map[string]any{"type": "X509", "flag": flag, "data": c}); err != nil {
			return "", err
		}
	}
	return certs[0], nil
}

// loadConn loads one connection, identified as id with the leaf certificate.
func (i *ikev2) loadConn(name, id, leaf string) error {
	conn := map[string]any{name: map[string]any{
		"version":   "2",
		"pools":     []string{"nomax4", "nomax6"},
		"proposals": ikeProposals,
		"send_cert": "always",
		"unique":    "replace",
		"dpd_delay": "30s",
		"local":     map[string]any{"auth": "pubkey", "id": id, "certs": []string{leaf}},
		"remote":    map[string]any{"auth": "eap-mschapv2", "eap_id": "%any"},
		"children": map[string]any{name: map[string]any{
			"local_ts":      []string{"0.0.0.0/0", "::/0"},
			"esp_proposals": espProposals,
			"dpd_action":    "clear",
		}},
	}}
	_, err := i.call("load-conn", conn)
	return err
}

type ikeSA struct {
	id       string // IKE_SA unique id
	user     string // EAP identity, which is the device's Email()
	children map[string]wgCounters
}

func (i *ikev2) sas() ([]ikeSA, error) {
	var msgs []*vici.Message
	for _, name := range []string{ikeConn, ikeConnV4} {
		m, err := i.stream("list-sas", "list-sa", map[string]any{"ike": name})
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, m...)
	}
	var out []ikeSA
	for _, m := range msgs {
		for _, k := range m.Keys() {
			sa, ok := m.Get(k).(*vici.Message)
			if !ok {
				continue
			}
			s := ikeSA{id: str(sa, "uniqueid"), user: str(sa, "remote-eap-id"), children: map[string]wgCounters{}}
			if s.user == "" {
				s.user = str(sa, "remote-id")
			}
			if cs, ok := sa.Get("child-sas").(*vici.Message); ok {
				for _, ck := range cs.Keys() {
					if c, ok := cs.Get(ck).(*vici.Message); ok {
						rx, _ := strconv.ParseInt(str(c, "bytes-in"), 10, 64)
						tx, _ := strconv.ParseInt(str(c, "bytes-out"), 10, 64)
						s.children[str(c, "uniqueid")] = wgCounters{rx: rx, tx: tx}
					}
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func (i *ikev2) terminate(users []string) error {
	sas, err := i.sas()
	if err != nil {
		return err
	}
	for _, sa := range sas {
		for _, u := range users {
			if sa.user == u {
				i.call("terminate", map[string]any{"ike-id": sa.id, "force": true, "timeout": -1})
			}
		}
	}
	return nil
}

// usage adds traffic since the last call per EAP identity; a connected SA counts as a handshake now.
func (i *ikev2) usage(add func(user string, rx, tx int64)) {
	sas, err := i.sas()
	if err != nil {
		return
	}
	live := map[string]wgCounters{}
	for _, sa := range sas {
		for id, cur := range sa.children {
			prev := i.seen[id]
			if cur.rx < prev.rx || cur.tx < prev.tx {
				prev = wgCounters{}
			}
			live[id] = cur
			add(sa.user, cur.rx-prev.rx, cur.tx-prev.tx)
		}
		if len(sa.children) == 0 {
			add(sa.user, 0, 0)
		}
	}
	i.seen = live
}

func str(m *vici.Message, key string) string {
	s, _ := m.Get(key).(string)
	return s
}
