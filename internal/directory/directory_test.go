package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testKeys(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret := make([]byte, 32)
	rand.Read(secret)
	PublicKey, Secret = base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(secret)
	t.Cleanup(func() { PublicKey, Secret, Name, GistURL = "", "", "", "" })
	return priv, secret
}

func TestSealOpen(t *testing.T) {
	priv, secret := testKeys(t)
	pub := priv.Public().(ed25519.PublicKey)
	e := Entry{T: 1, Host: "example.test", IPs: []string{"192.0.2.1", "2001:db8::1"}, Relays: []string{"198.51.100.7"}}
	blob, err := Seal(e, priv, secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, "example") || strings.Contains(blob, "192.0.2.1") {
		t.Fatal("the entry shows through")
	}
	got, err := Open(blob, pub, secret)
	if err != nil || got.Host != e.Host || len(got.IPs) != 2 || got.Relays[0] != "198.51.100.7" {
		t.Fatalf("got %+v, %v", got, err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := Seal(e, other, secret)
	if _, err := Open(forged, pub, secret); err == nil {
		t.Fatal("an entry signed by another key opened")
	}
	if _, err := Open(blob, pub, make([]byte, 32)); err == nil {
		t.Fatal("an entry opened with the wrong secret")
	}
	if txt := TXT(strings.Repeat("a", 600)); txt != `"`+strings.Repeat("a", 255)+`" "`+strings.Repeat("a", 255)+`" "`+strings.Repeat("a", 90)+`"` {
		t.Fatalf("TXT split: %s", txt)
	}
}

func TestLookup(t *testing.T) {
	priv, secret := testKeys(t)
	old, _ := Seal(Entry{T: 100, Host: "example.test", IPs: []string{"192.0.2.1"}}, priv, secret)
	fresh, _ := Seal(Entry{T: 200, Host: "example.test", IPs: []string{"192.0.2.2"}, Relays: []string{"198.51.100.7"}}, priv, secret)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := Seal(Entry{T: 300, Host: "evil.test"}, other, secret)

	// The resolver has the old entry and a forged newer one; the gist has the fresh one.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gist" {
			io.WriteString(w, fresh+"\n")
			return
		}
		q, _ := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		var p dnsmessage.Parser
		h, _ := p.Start(q)
		question, _ := p.Question()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
		b.StartQuestions()
		b.Question(question)
		b.StartAnswers()
		hdr := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}
		b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{old[:200], old[200:]}})
		b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{forged}})
		msg, _ := b.Finish()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(msg)
	}))
	defer srv.Close()
	savedResolvers, savedClient := resolvers, client
	defer func() { resolvers, client = savedResolvers, savedClient }()
	resolvers, client = []string{srv.URL + "/dns-query"}, srv.Client()

	Name = "dir.invalid"
	cached = nil
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, err := Lookup(ctx)
	if err != nil || e.T != 100 {
		t.Fatalf("from DNS alone: %+v, %v", e, err)
	}

	GistURL = srv.URL + "/gist"
	cached = nil
	e, err = Lookup(ctx)
	if err != nil || e.T != 200 || e.Relays[0] != "198.51.100.7" {
		t.Fatalf("newest: %+v, %v", e, err)
	}
	if !e.Differs("example.test", []string{"192.0.2.1"}, nil) || e.Differs("example.test", []string{"192.0.2.2"}, []string{"198.51.100.7"}) {
		t.Fatal("Differs")
	}

	PublicKey = ""
	if _, err := Lookup(ctx); err == nil {
		t.Fatal("a build without the directory looked it up")
	}
}
