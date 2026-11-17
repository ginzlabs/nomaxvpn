// Package directory is where the apps find the server when every way they
// know has stopped working: a small entry with the server's name, its
// addresses and the relays, signed with Ed25519 and encrypted with a key the
// apps carry. `make publish` puts it in a DNS TXT record, which the apps read
// over DNS-over-HTTPS from Yandex, Google and Cloudflare and through the
// system's resolver, and in a GitHub gist. The newest entry that checks out
// wins.
package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/dns/dnsmessage"
)

// Set when the apps are built (-X github.com/ginzlabs/nomaxvpn/internal/directory.…)
// from DIRECTORY_PUBLIC, DIRECTORY_SECRET, DIRECTORY_NAME and DIRECTORY_GIST.
var (
	PublicKey string // base64 Ed25519 public key
	Secret    string // base64, 32 bytes
	Name      string // the TXT record's name
	GistURL   string // the gist file's raw URL
)

// Entry is what the directory says.
type Entry struct {
	// T is when it was published (Unix seconds); the newest wins.
	T      int64    `json:"t"`
	Host   string   `json:"host"`
	IPs    []string `json:"ips,omitempty"`
	Relays []string `json:"relays,omitempty"`
}

const (
	prefix = "n1"
	label  = "nomax directory"
)

// Seal signs and encrypts e for publishing.
func Seal(e Entry, sign ed25519.PrivateKey, secret []byte) (string, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	plain := append(ed25519.Sign(sign, body), body...)
	return prefix + base64.RawStdEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(label))), nil
}

// Open decrypts blob and checks its signature.
func Open(blob string, pub ed25519.PublicKey, secret []byte) (Entry, error) {
	var e Entry
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(blob), prefix))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(blob), prefix) {
		return e, errors.New("not a directory entry")
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return e, err
	}
	if len(raw) < aead.NonceSize() {
		return e, errors.New("directory entry too short")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(label))
	if err != nil {
		return e, errors.New("directory entry doesn't decrypt")
	}
	if len(plain) < ed25519.SignatureSize || !ed25519.Verify(pub, plain[ed25519.SignatureSize:], plain[:ed25519.SignatureSize]) {
		return e, errors.New("directory entry isn't signed by us")
	}
	if err := json.Unmarshal(plain[ed25519.SignatureSize:], &e); err != nil {
		return e, err
	}
	if e.Host == "" {
		return e, errors.New("directory entry has no host")
	}
	return e, nil
}

// TXT splits blob into the 255-byte strings of a TXT record, as Cloudflare
// takes them: "…" "…".
func TXT(blob string) string {
	var parts []string
	for len(blob) > 255 {
		parts = append(parts, `"`+blob[:255]+`"`)
		blob = blob[255:]
	}
	return strings.Join(append(parts, `"`+blob+`"`), " ")
}

// resolvers answer DNS-over-HTTPS (RFC 8484).
var resolvers = []string{
	"https://common.dot.dns.yandex.net/dns-query",
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
}

var (
	cacheMu sync.Mutex
	cached  *Entry
	cacheAt time.Time
)

// cacheFor keeps an answer, so reconnects that keep failing don't ask again each time.
const cacheFor = 5 * time.Minute

// Lookup asks every place at once and returns the newest entry that checks
// out, within ctx (or 10 s).
func Lookup(ctx context.Context) (Entry, error) {
	pub, secret, err := keys()
	if err != nil {
		return Entry{}, err
	}
	cacheMu.Lock()
	if cached != nil && time.Since(cacheAt) < cacheFor {
		e := *cached
		cacheMu.Unlock()
		return e, nil
	}
	cacheMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var sources []func(context.Context) ([]string, error)
	if Name != "" {
		for _, r := range resolvers {
			sources = append(sources, func(ctx context.Context) ([]string, error) { return doh(ctx, r, Name) })
		}
		sources = append(sources, func(ctx context.Context) ([]string, error) { return net.DefaultResolver.LookupTXT(ctx, Name) })
	}
	if GistURL != "" {
		sources = append(sources, func(ctx context.Context) ([]string, error) { return fetch(ctx, GistURL) })
	}
	if len(sources) == 0 {
		return Entry{}, errors.New("no directory in this build")
	}
	found := make(chan *Entry, len(sources))
	for _, src := range sources {
		go func() {
			blobs, _ := src(ctx)
			var best *Entry
			for _, b := range blobs {
				if e, err := Open(b, pub, secret); err == nil && (best == nil || e.T > best.T) {
					best = &e
				}
			}
			found <- best
		}()
	}
	// The first answer that checks out may be stale; give the rest a moment.
	var best *Entry
	var grace <-chan time.Time
	for range sources {
		select {
		case e := <-found:
			if e != nil && (best == nil || e.T > best.T) {
				best = e
				if grace == nil {
					grace = time.After(1500 * time.Millisecond)
				}
			}
			continue
		case <-grace:
		case <-ctx.Done():
		}
		break
	}
	if best == nil {
		return Entry{}, errors.New("the directory didn't answer")
	}
	cacheMu.Lock()
	cached, cacheAt = best, time.Now()
	cacheMu.Unlock()
	return *best, nil
}

func keys() (ed25519.PublicKey, []byte, error) {
	pub, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, errors.New("no directory in this build")
	}
	secret, err := base64.StdEncoding.DecodeString(Secret)
	if err != nil || len(secret) != chacha20poly1305.KeySize {
		return nil, nil, errors.New("no directory in this build")
	}
	return pub, secret, nil
}

// client goes straight out, never through a proxy the system may have.
var client = &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}

// doh asks resolver for name's TXT records over DNS-over-HTTPS.
func doh(ctx context.Context, resolver, name string) ([]string, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", resolver+"?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	if _, err := p.Start(body); err != nil {
		return nil, err
	}
	p.SkipAllQuestions()
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type != dnsmessage.TypeTXT {
			p.SkipAnswer()
			continue
		}
		r, err := p.TXTResource()
		if err != nil {
			break
		}
		out = append(out, strings.Join(r.TXT, ""))
	}
	return out, nil
}

// fetch reads a file of entries, one per line.
func fetch(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(bytes.TrimSpace(body))), nil
}

// Differs says whether e has addresses or relays the caller doesn't know.
func (e Entry) Differs(host string, ips, relays []string) bool {
	if e.Host != host {
		return true
	}
	for _, ip := range e.IPs {
		if !slices.Contains(ips, ip) {
			return true
		}
	}
	for _, r := range e.Relays {
		if !slices.Contains(relays, r) {
			return true
		}
	}
	return false
}
