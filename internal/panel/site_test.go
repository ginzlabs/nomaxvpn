package panel_test

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/panel"
	"github.com/ginzlabs/nomaxvpn/internal/store"
)

func fetch(t *testing.T, srv *httptest.Server, method, path, token string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// allowed reports whether the page's CSP allows its inline element by hash.
func allowed(page string, h http.Header, tag string) bool {
	_, s, _ := strings.Cut(page, "<"+tag+">")
	s, _, ok := strings.Cut(s, "</"+tag+">")
	sum := sha256.Sum256([]byte(s))
	return ok && strings.Contains(h.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
}

func TestSite(t *testing.T) {
	srv, _, _ := setup(t)

	code, page, h := fetch(t, srv, "GET", "/", "")
	if code != 200 || !strings.Contains(page, "<title>Example</title>") {
		t.Fatalf("home page: %d", code)
	}
	saysNothing(t, "home", page)
	if !allowed(page, h, "script") || !allowed(page, h, "style") {
		t.Fatalf("the home page's CSP doesn't allow its own script and style: %s", h.Get("Content-Security-Policy"))
	}
	for _, leak := range []string{adminPath, filesPath, privacyPath, "nomax", "NoMax", "privacy", "VPN"} {
		if strings.Contains(page, leak) {
			t.Errorf("home page mentions %q", leak)
		}
	}

	for _, path := range []string{"/privacy", "/join", "/nomax.apk", "/nomax-setup.exe", "/s.css", "/admin", "/files", "/" + filesPath + "x"} {
		if code, _, _ := fetch(t, srv, "GET", path, ""); code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, code)
		}
	}

	code, page, h = fetch(t, srv, "GET", "/"+privacyPath, "")
	if code != 200 || !strings.Contains(page, "What the server stores") {
		t.Fatalf("privacy: %d", code)
	}
	saysNothing(t, "privacy", page)
	if !allowed(page, h, "style") {
		t.Fatal("the pages' CSP doesn't allow their inline style")
	}
}

func TestShortSecretPathsAreNotServed(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := panel.Config{Host: "vpn.test", FilesPath: "files", PrivacyPath: "/"}
	srv := httptest.NewTLSServer(panel.New(cfg, st, fakeVPN{}, func() {}, slog.New(slog.DiscardHandler)).Handler())
	defer srv.Close()
	if code, _, _ := fetch(t, srv, "GET", "/files", ""); code != http.StatusNotFound {
		t.Errorf("short files path served: %d", code)
	}
	if _, page, _ := fetch(t, srv, "GET", "/", ""); !strings.Contains(page, "<title>Vpn</title>") {
		t.Error("an empty privacy path replaced the home page")
	}
}

func TestSecretAPIPath(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := panel.Config{Host: "vpn.test", APIPath: "secret-api-path"}
	srv := httptest.NewTLSServer(panel.New(cfg, st, fakeVPN{}, func() {}, slog.New(slog.DiscardHandler)).Handler())
	defer srv.Close()
	person, _ := st.CreatePerson("Alice", 2)
	_, token, err := st.Enroll(newPIN(t, st, person.ID), "Phone", wgPub(t))
	if err != nil {
		t.Fatal(err)
	}

	if code, _, _ := fetch(t, srv, "GET", "/secret-api-path/v1/profile", token); code != 200 {
		t.Fatalf("profile on the secret path: %d", code)
	}
	if code, _, _ := fetch(t, srv, "GET", "/secret-api-path/v1/profile", ""); code != http.StatusUnauthorized {
		t.Fatalf("secret path without a token: %d", code)
	}
	if code, _, _ := fetch(t, srv, "GET", "/api/v1/profile", token); code != 200 {
		t.Fatalf("an older app's profile: %d", code)
	}
	for _, c := range []struct{ method, path, token string }{
		{"GET", "/api/v1/profile", ""},
		{"GET", "/api/v1/profile", "not-a-token"},
		{"POST", "/api/v1/enroll", ""},
		{"GET", "/api/v1/check?bytes=1024", ""},
		{"POST", "/api/v1/report", "not-a-token"},
	} {
		if code, _, _ := fetch(t, srv, c.method, c.path, c.token); code != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c.method, c.path, code)
		}
	}
}
