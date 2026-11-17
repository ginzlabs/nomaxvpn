package panel_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/panel"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
)

const (
	adminPath   = "secret-admin-path"
	filesPath   = "secret-files-path"
	privacyPath = "secret-privacy-path"
)

type fakeVPN struct{}

func (fakeVPN) Profile(d store.Device) profile.Profile {
	return profile.Profile{Host: "example.test", Reality: profile.RealityConf{UUID: d.UUID}}
}
func (fakeVPN) HasHysteria() bool { return false }
func (fakeVPN) OpenVPNConfig(d store.Device) (string, error) {
	return "client\n# " + d.UUID + "\n", nil
}

func setup(t *testing.T) (*httptest.Server, *store.Store, *int) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kicks := new(int)
	p := panel.New(panel.Config{Host: "example.test", AdminPath: adminPath, FilesPath: filesPath, PrivacyPath: privacyPath}, st, fakeVPN{}, func() { *kicks++ }, slog.New(slog.DiscardHandler))
	srv := httptest.NewTLSServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv, st, kicks
}

// The site mustn't say what it's for. Inline CSS (font-family) and embedded
// files (base64) aren't words, so they're left out of the check.
var notWords = regexp.MustCompile(`(?s)<style>.*?</style>|data:[^"]*`)

func saysNothing(t *testing.T, name, page string) {
	t.Helper()
	text := strings.ToLower(notWords.ReplaceAllString(page, ""))
	for _, word := range []string{"vpn"} {
		if strings.Contains(text, word) {
			t.Errorf("%s page says %q", name, word)
		}
	}
}

func enroll(t *testing.T, srv *httptest.Server, pin, key string) (int, map[string]any) {
	return enrollFrom(t, srv, "", pin, key)
}

// enrollFrom sends the request as if from ip (the panel trusts X-Forwarded-For on loopback).
func enrollFrom(t *testing.T, srv *httptest.Server, ip, pin, key string) (int, map[string]any) {
	body := `{"pin":"` + pin + `","deviceName":"iPhone","wgPublicKey":"` + key + `"}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/enroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func wgPub(t *testing.T) string {
	k, err := profile.WireGuardPublic(profile.NewWireGuardKey())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func authed(t *testing.T, srv *httptest.Server, method, token string) int {
	req, _ := http.NewRequest(method, srv.URL+"/api/v1/"+map[string]string{"GET": "profile", "DELETE": "device"}[method], nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestTrace(t *testing.T) {
	hits := 0
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		io.WriteString(w, "ip=192.0.2.7\nloc=GB\ncolo=LHR\n")
	}))
	t.Cleanup(cf.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p := panel.New(panel.Config{Host: "vpn.test", TraceURL: cf.URL}, st, fakeVPN{}, func() {}, slog.New(slog.DiscardHandler))
	srv := httptest.NewTLSServer(p.Handler())
	t.Cleanup(srv.Close)

	person, _ := st.CreatePerson("Bob", 1)
	code, m := enroll(t, srv, newPIN(t, st, person.ID), wgPub(t))
	if code != http.StatusOK {
		t.Fatalf("enroll: %d", code)
	}
	get := func(token string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/trace", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, _ := get("nope"); c != http.StatusUnauthorized {
		t.Fatalf("trace without a device: %d", c)
	}
	for range 2 {
		if c, body := get(m["deviceToken"].(string)); c != http.StatusOK || !strings.Contains(body, "colo=LHR") {
			t.Fatalf("trace: %d %q", c, body)
		}
	}
	if hits != 1 {
		t.Fatalf("trace fetched %d times, want 1 (cached)", hits)
	}
}

func newPIN(t *testing.T, st *store.Store, id int64) string {
	pin, err := st.NewPIN(id)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func TestDeviceLifecycle(t *testing.T) {
	srv, st, kicks := setup(t)
	person, err := st.CreatePerson("Alice", 2)
	if err != nil {
		t.Fatal(err)
	}

	pin := newPIN(t, st, person.ID)
	wrong := "000000"
	if pin == wrong {
		wrong = "000001"
	}
	if code, _ := enroll(t, srv, wrong, wgPub(t)); code != http.StatusForbidden {
		t.Fatalf("bad PIN: %d", code)
	}
	if code, _ := enroll(t, srv, pin, "not-a-key"); code != http.StatusBadRequest {
		t.Fatalf("bad key: %d", code)
	}

	code, m := enroll(t, srv, pin[:2]+" "+pin[2:], wgPub(t))
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %v", code, m)
	}
	if code, _ := enroll(t, srv, pin, wgPub(t)); code != http.StatusForbidden {
		t.Fatalf("PIN reused: %d", code)
	}
	token := m["deviceToken"].(string)
	if *kicks != 1 {
		t.Fatalf("enroll should kick the runtime, kicks=%d", *kicks)
	}
	if c := authed(t, srv, "GET", token); c != http.StatusOK {
		t.Fatalf("profile: %d", c)
	}
	if c := authed(t, srv, "GET", "nope"); c != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", c)
	}

	if code, _ := enroll(t, srv, newPIN(t, st, person.ID), wgPub(t)); code != http.StatusOK {
		t.Fatalf("second device: %d", code)
	}
	if code, _ := enroll(t, srv, newPIN(t, st, person.ID), wgPub(t)); code != http.StatusConflict {
		t.Fatalf("over limit: %d", code)
	}

	st.SetDisabled(person.ID, true)
	if c := authed(t, srv, "GET", token); c != http.StatusUnauthorized {
		t.Fatalf("disabled person still served: %d", c)
	}
	st.SetDisabled(person.ID, false)

	if c := authed(t, srv, "DELETE", token); c != http.StatusNoContent {
		t.Fatalf("delete: %d", c)
	}
	if c := authed(t, srv, "GET", token); c != http.StatusUnauthorized {
		t.Fatalf("deleted device still served: %d", c)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	srv, st, _ := setup(t)
	for range 5 {
		if code, _ := enrollFrom(t, srv, "203.0.113.1", "999999", wgPub(t)); code != http.StatusForbidden {
			t.Fatalf("wrong PIN: %d", code)
		}
	}
	if code, _ := enrollFrom(t, srv, "203.0.113.1", "999999", wgPub(t)); code != http.StatusTooManyRequests {
		t.Fatalf("per-IP limit: %d", code)
	}

	for i := range 25 {
		enrollFrom(t, srv, "198.51.100."+strconv.Itoa(i), "999999", wgPub(t))
	}
	person, _ := st.CreatePerson("Kid", 1)
	pin := newPIN(t, st, person.ID)
	if code, _ := enrollFrom(t, srv, "192.0.2.1", pin, wgPub(t)); code != http.StatusTooManyRequests {
		t.Fatalf("global pause should block even a valid PIN: %d", code)
	}
	st.ClearFailures(store.EnrollPIN)
	if code, m := enrollFrom(t, srv, "192.0.2.1", pin, wgPub(t)); code != http.StatusOK {
		t.Fatalf("after resume: %d %v", code, m)
	}
}

func TestReEnrollSameKeyReplaces(t *testing.T) {
	srv, st, _ := setup(t)
	person, _ := st.CreatePerson("Bob", 1)
	key := wgPub(t)
	for range 3 {
		if code, m := enroll(t, srv, newPIN(t, st, person.ID), key); code != http.StatusOK {
			t.Fatalf("re-enroll: %d %v", code, m)
		}
	}
	devs, _ := st.Devices(false)
	if len(devs) != 1 {
		t.Fatalf("want 1 device, got %d", len(devs))
	}
}

func adminClient(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func post(t *testing.T, c *http.Client, u string, form url.Values) *http.Response {
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAdmin(t *testing.T) {
	srv, st, _ := setup(t)
	st.SetSetting(panel.AdminHashKey, panel.HashCode("correct horse battery"))
	c := adminClient(srv)
	admin := srv.URL + "/" + adminPath

	if code, _ := get(t, c, srv.URL+"/admin"); code != http.StatusNotFound {
		t.Fatalf("guessable admin path: %d", code)
	}
	if code, body := get(t, c, srv.URL+"/"); code != 200 || strings.Contains(body, adminPath) {
		t.Fatalf("home leaks admin path or fails: %d", code)
	}
	code, body := get(t, c, admin)
	if code != 200 || !strings.Contains(body, "Admin code") {
		t.Fatalf("login page: %d", code)
	}
	saysNothing(t, "login", body)
	if r := post(t, c, admin+"/people", url.Values{"name": {"Eve"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauthenticated add: %d", r.StatusCode)
	}
	if p, _ := st.People(); len(p) != 0 {
		t.Fatal("unauthenticated add created a person")
	}

	if r := post(t, c, admin+"/login", url.Values{"code": {"correct horse battery"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if r := post(t, c, admin+"/people", url.Values{"name": {"Carol"}, "max": {"2"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("add person: %d", r.StatusCode)
	}
	code, body = get(t, c, admin)
	if code != 200 || !strings.Contains(body, "Carol") {
		t.Fatalf("dashboard: %d", code)
	}
	saysNothing(t, "dashboard", body)
	people, _ := st.People()
	if people[0].PIN == "" {
		t.Fatal("adding a person should open an invite")
	}
	code, body = get(t, c, admin+"/people/1")
	if code != 200 || !strings.Contains(body, people[0].PIN) || !strings.Contains(body, "nomax://join?pin=") || !strings.Contains(body, "data:image/png") {
		t.Fatalf("invite page: %d", code)
	}
	saysNothing(t, "invite", body)
	if r := post(t, c, admin+"/people/1/pin", nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("new PIN: %d", r.StatusCode)
	}

	for i := range 30 {
		st.RecordFailure(store.EnrollPIN, "198.51.100."+strconv.Itoa(i))
	}
	if _, body := get(t, c, admin); !strings.Contains(body, "Resume now") {
		t.Fatal("dashboard should offer to resume joining")
	}
	post(t, c, admin+"/resume", nil)
	if _, body := get(t, c, admin); strings.Contains(body, "Resume now") {
		t.Fatal("resume did not clear the pause")
	}

	req, _ := http.NewRequest("POST", admin+"/people/1/delete", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, _ := c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d", resp.StatusCode)
	}
	if p, _ := st.People(); len(p) != 1 {
		t.Fatal("cross-site POST deleted a person")
	}
}

func TestAdminLockout(t *testing.T) {
	srv, st, _ := setup(t)
	st.SetSetting(panel.AdminHashKey, panel.HashCode("correct horse battery"))
	c := adminClient(srv)
	admin := srv.URL + "/" + adminPath
	for range 10 {
		if r := post(t, c, admin+"/login", url.Values{"code": {"guess"}}); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code: %d", r.StatusCode)
		}
	}
	if code, _ := get(t, c, admin); code != http.StatusNotFound {
		t.Fatalf("locked out IP should get 404, got %d", code)
	}
	if r := post(t, c, admin+"/login", url.Values{"code": {"correct horse battery"}}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("correct code during lockout: %d", r.StatusCode)
	}
	st.ResetAdmin()
	if r := post(t, c, admin+"/login", url.Values{"code": {"correct horse battery"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("after reset: %d", r.StatusCode)
	}
}

func TestCodeHash(t *testing.T) {
	h := panel.HashCode("abc123abc123")
	if !panel.CheckCode("abc123abc123", h) || panel.CheckCode("abc123abc124", h) || panel.CheckCode("x", "garbage") {
		t.Fatal("hash check")
	}
}

func TestWebJoin(t *testing.T) {
	srv, st, kicks := setup(t)
	person, err := st.CreatePerson("Gran", 2)
	if err != nil {
		t.Fatal(err)
	}
	post := func(pin string) (int, string) {
		resp, err := srv.Client().PostForm(srv.URL+"/"+filesPath, url.Values{"pin": {pin}, "name": {"Gran's laptop"}})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, form := get(t, srv.Client(), srv.URL+"/"+filesPath)
	if code != 200 {
		t.Fatalf("GET files page: %d", code)
	}
	saysNothing(t, "join", form)
	if code, body := post("000000"); code != http.StatusForbidden || !strings.Contains(body, "PIN doesn") {
		t.Fatalf("wrong PIN: %d", code)
	}
	pin := newPIN(t, st, person.ID)
	code, body := post(pin)
	if code != 200 {
		t.Fatalf("join: %d %s", code, body)
	}
	for _, want := range []string{"Gran&#39;s laptop is ready", "PrivateKey = ", "vless://"} {
		if !strings.Contains(body, want) {
			t.Fatalf("configs page lacks %q", want)
		}
	}
	saysNothing(t, "configs", body)
	devs, _ := st.Devices(true)
	if len(devs) != 1 || devs[0].Name != "Gran's laptop" || *kicks == 0 {
		t.Fatalf("devices %+v kicks %d", devs, *kicks)
	}
	if code, _ := post(pin); code != http.StatusForbidden {
		t.Fatalf("PIN reused: %d", code)
	}
}

func TestCheckDownload(t *testing.T) {
	srv, _, _ := setup(t)
	resp, err := srv.Client().Get(srv.URL + "/api/v1/check?bytes=65536")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(b) != 65536 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("check download: %d, %d bytes, %q", resp.StatusCode, len(b), resp.Header.Get("Cache-Control"))
	}
	if resp, _ := srv.Client().Get(srv.URL + "/api/v1/check?bytes=999999999"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("too big: %d", resp.StatusCode)
	}
}

func TestAppDownloads(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	exe := filepath.Join(t.TempDir(), "nomax-setup.exe")
	cfg := panel.Config{Host: "vpn.test", FilesPath: filesPath, APKPath: filepath.Join(t.TempDir(), "missing.apk"), WindowsPath: exe}
	srv := httptest.NewTLSServer(panel.New(cfg, st, fakeVPN{}, func() {}, slog.New(slog.DiscardHandler)).Handler())
	defer srv.Close()
	get := func(path string) (int, string, http.Header) {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	files := "/" + filesPath
	if code, _, _ := get(files + "/vpn-setup.exe"); code != http.StatusNotFound {
		t.Fatalf("installer before upload: %d", code)
	}
	if _, page, _ := get(files); strings.Contains(page, "vpn-setup.exe") {
		t.Fatal("files page links a missing installer")
	}
	if err := os.WriteFile(exe, []byte("MZ installer"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body, h := get(files + "/vpn-setup.exe")
	if code != 200 || body != "MZ installer" || !strings.Contains(h.Get("Content-Disposition"), `"vpn-setup.exe"`) {
		t.Fatalf("installer: %d %q %q", code, body, h.Get("Content-Disposition"))
	}
	if _, page, _ := get(files); !strings.Contains(page, `href="`+files+`/vpn-setup.exe"`) || strings.Contains(page, "vpn.apk") {
		t.Fatal("files page should link the Windows installer and not the missing APK")
	}
	if code, _, _ := get("/nomax-setup.exe"); code != http.StatusNotFound {
		t.Fatalf("public installer path: %d", code)
	}
}

func TestClientIPThroughCloudflare(t *testing.T) {
	for _, c := range []struct{ remote, cf, want string }{
		{"104.16.1.1:443", "203.0.113.5", "203.0.113.5"},
		{"[2606:4700::1]:443", "2001:db8::5", "2001:db8::5"},
		{"198.51.100.1:443", "203.0.113.5", "198.51.100.1"},
		{"104.16.1.1:443", "", "104.16.1.1"},
		{"104.16.1.1:443", "not an address", "104.16.1.1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.cf != "" {
			r.Header.Set("CF-Connecting-IP", c.cf)
		}
		if got := panel.ClientIP(r); got != c.want {
			t.Errorf("from %s naming %q: got %s, want %s", c.remote, c.cf, got, c.want)
		}
	}
}
