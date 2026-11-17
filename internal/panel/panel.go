// Package panel serves the device API, the public pages and the hidden admin panel.
package panel

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"rsc.io/qr"
)

const (
	AdminHashKey  = "admin_hash"
	sessionCookie = "__Host-nomax"
	sessionTTL    = 30 * 24 * time.Hour

	ipFailLimit     = 10
	globalFailLimit = 100

	// Wrong PINs: per-IP limit, and a global limit that pauses joining for everyone.
	enrollWindow   = 15 * time.Minute
	enrollIPLimit  = 5
	enrollAllLimit = 30

	defaultTraceURL = "https://1.1.1.1/cdn-cgi/trace"
	traceTTL        = 5 * time.Minute
)

//go:embed web
var web embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"bytes": humanBytes,
	"ago":   ago,
	"left":  left,
	"pin":   formatPIN,
	"css":   func() template.CSS { return template.CSS(style) },
}).ParseFS(web, "web/*.html"))

// Config is the panel's setup. Besides the home page at /, the site only answers
// on secret paths; one shorter than 8 characters isn't served.
type Config struct {
	Host      string
	AdminPath string
	// APIPath is the device API's first path segment ("api" when empty).
	APIPath string
	// FilesPath has the apps' downloads and the join form for other apps.
	FilesPath string
	// PrivacyPath is the privacy policy, for Apple.
	PrivacyPath   string
	TestFlightURL string
	Version       string
	APKPath       string // the Android app, served under FilesPath when present
	WindowsPath   string // the Windows installer, likewise
	TraceURL      string // Cloudflare's trace page; empty means 1.1.1.1
}

// Profiles builds a device's profile and reports server state.
type Profiles interface {
	Profile(store.Device) profile.Profile
	OpenVPNConfig(store.Device) (string, error)
	HasHysteria() bool
}

type Panel struct {
	cfg     Config
	st      *store.Store
	vpn     Profiles
	kick    func()
	log     *slog.Logger
	started time.Time
	admin   string
	trace   traceCache

	reportLimit rateLimit
}

func New(cfg Config, st *store.Store, vpn Profiles, kick func(), log *slog.Logger) *Panel {
	if cfg.TraceURL == "" {
		cfg.TraceURL = defaultTraceURL
	}
	return &Panel{cfg: cfg, st: st, vpn: vpn, kick: kick, log: log, started: time.Now(), admin: "/" + strings.Trim(cfg.AdminPath, "/")}
}

func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)

	api := profile.APIBase(p.cfg.APIPath)
	mux.HandleFunc("POST "+api+"/enroll", p.enroll)
	mux.HandleFunc("GET "+api+"/profile", p.device(p.getProfile))
	mux.HandleFunc("GET "+api+"/openvpn", p.device(p.getOpenVPN))
	mux.HandleFunc("GET "+api+"/trace", p.device(p.getTrace))
	mux.HandleFunc("GET "+api+"/check", serveCheck)
	mux.HandleFunc("DELETE "+api+"/device", p.device(p.deleteDevice))
	mux.HandleFunc("POST "+api+"/report", p.device(p.postReport))
	if legacy := profile.APIBase(""); api != legacy {
		// Apps from before the secret path: only their devices get an answer.
		mux.HandleFunc("GET "+legacy+"/profile", p.legacy(p.getProfile))
		mux.HandleFunc("GET "+legacy+"/openvpn", p.legacy(p.getOpenVPN))
		mux.HandleFunc("GET "+legacy+"/trace", p.legacy(p.getTrace))
		mux.HandleFunc("DELETE "+legacy+"/device", p.legacy(p.deleteDevice))
		mux.HandleFunc("POST "+legacy+"/report", p.legacy(p.postReport))
	}

	if files, ok := secret(p.cfg.FilesPath); ok {
		mux.HandleFunc("GET "+files, p.joinForm)
		mux.HandleFunc("POST "+files, p.join)
		mux.HandleFunc("GET "+files+"/"+p.apkName(), download(p.cfg.APKPath, "application/vnd.android.package-archive", p.apkName()))
		mux.HandleFunc("GET "+files+"/"+p.exeName(), download(p.cfg.WindowsPath, "application/vnd.microsoft.portable-executable", p.exeName()))
	}
	if privacy, ok := secret(p.cfg.PrivacyPath); ok {
		mux.HandleFunc("GET "+privacy, p.page("privacy"))
	}

	if len(p.cfg.AdminPath) >= 8 {
		a := http.NewServeMux()
		a.HandleFunc("GET "+p.admin, p.dashboard)
		a.HandleFunc("POST "+p.admin+"/login", p.login)
		a.HandleFunc("POST "+p.admin+"/logout", p.authed(p.logout))
		a.HandleFunc("POST "+p.admin+"/people", p.authed(p.addPerson))
		a.HandleFunc("GET "+p.admin+"/people/{id}", p.authed(p.invite))
		a.HandleFunc("POST "+p.admin+"/people/{id}/{action}", p.authed(p.personAction))
		a.HandleFunc("POST "+p.admin+"/devices/{id}/delete", p.authed(p.deleteDeviceAdmin))
		a.HandleFunc("POST "+p.admin+"/resume", p.authed(p.resume))
		guarded := p.lockout(http.NewCrossOriginProtection().Handler(a))
		mux.Handle(p.admin, guarded)
		mux.Handle(p.admin+"/", guarded)
	}
	return secureHeaders(mux)
}

func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src "+styleHash+"; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func (p *Panel) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.render(w, name, map[string]any{"Cfg": p.cfg})
	}
}

func (p *Panel) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		p.log.Error("render", "page", name, "err", err)
	}
}

// ClientIP is the visitor's address. The panel only listens on loopback, behind
// PROXY protocol (Reality fallback) or the Hysteria2 masquerade (X-Forwarded-For).
// Visits through Cloudflare's proxy come from Cloudflare, which names the visitor.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if ip = ip.Unmap(); ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	if fromCloudflare(ip) {
		if v, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
			return v.String()
		}
	}
	return host
}

// cloudflare holds Cloudflare's published ranges (cloudflare.com/ips).
var cloudflare = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range strings.Fields(`
		173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
		108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17
		162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
		2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32
		2a06:98c0::/29 2c0f:f248::/32`) {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

func fromCloudflare(ip netip.Addr) bool {
	for _, p := range cloudflare {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// checkData is random so nothing on the way can compress it.
var checkData = func() []byte {
	b := make([]byte, 256<<10)
	rand.Read(b)
	return b
}()

// serveCheck sends ?bytes=n of data for the apps' connection check, which
// watches for networks that stall a download after its first few kilobytes.
func serveCheck(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
	if err != nil || n < 0 || n > len(checkData) {
		http.Error(w, "bytes must be 0 to 262144", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Write(checkData[:n])
}

// --- device API ---

type enrollReq struct {
	PIN         string `json:"pin"`
	DeviceName  string `json:"deviceName"`
	WGPublicKey string `json:"wgPublicKey"`
}

type enrollResp struct {
	DeviceToken string          `json:"deviceToken"`
	Profile     profile.Profile `json:"profile"`
}

func (p *Panel) enrollPaused() bool {
	n, _ := p.st.Failures(store.EnrollPIN, "", time.Now().Add(-enrollWindow))
	return n >= enrollAllLimit
}

func (p *Panel) enroll(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	if status, msg := p.joinGate(ip); status != 0 {
		jsonErr(w, status, msg)
		return
	}
	var req enrollReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "Bad request.")
		return
	}
	if !profile.ValidWireGuardKey(req.WGPublicKey) {
		jsonErr(w, http.StatusBadRequest, "Bad device key.")
		return
	}
	dev, token, err := p.st.Enroll(req.PIN, req.DeviceName, req.WGPublicKey)
	if err != nil {
		status, msg := p.joinError(ip, err)
		jsonErr(w, status, msg)
		return
	}
	p.log.Info("enrolled", "device", dev.ID, "person", dev.PersonName)
	p.kick()
	writeJSON(w, http.StatusOK, enrollResp{DeviceToken: token, Profile: p.vpn.Profile(dev)})
}

func (p *Panel) device(next func(http.ResponseWriter, *http.Request, store.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			jsonErr(w, http.StatusUnauthorized, "Not enrolled.")
			return
		}
		dev, err := p.st.DeviceByToken(token)
		if err != nil {
			jsonErr(w, http.StatusUnauthorized, "This device was removed. Ask for a new PIN to join again.")
			return
		}
		next(w, r, dev)
	}
}

func (p *Panel) getProfile(w http.ResponseWriter, r *http.Request, d store.Device) {
	p.st.Touch(d.ID)
	writeJSON(w, http.StatusOK, p.vpn.Profile(d))
}

func (p *Panel) getOpenVPN(w http.ResponseWriter, r *http.Request, d store.Device) {
	conf, err := p.vpn.OpenVPNConfig(d)
	if err != nil {
		jsonErr(w, http.StatusServiceUnavailable, "OpenVPN isn't available on this server.")
		return
	}
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.Header().Set("Content-Disposition", `attachment; filename="nomax.ovpn"`)
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, conf)
}

// getTrace returns Cloudflare's trace page as this server sees it: the address
// and location websites see from a connected device. The Android app asks here
// while connected because it is excluded from its own VPN.
func (p *Panel) getTrace(w http.ResponseWriter, r *http.Request, _ store.Device) {
	body, err := p.trace.get(r.Context(), p.cfg.TraceURL)
	if err != nil {
		p.log.Warn("trace", "err", err)
		jsonErr(w, http.StatusBadGateway, "Couldn't reach Cloudflare.")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(body)
}

type traceCache struct {
	mu   sync.Mutex
	body []byte
	at   time.Time
}

func (c *traceCache) get(ctx context.Context, url string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.body != nil && time.Since(c.at) < traceTTL {
		return c.body, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	c.body, c.at = b, time.Now()
	return b, nil
}

func (p *Panel) deleteDevice(w http.ResponseWriter, r *http.Request, d store.Device) {
	if err := p.st.DeleteDevice(d.ID); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Server error.")
		return
	}
	p.kick()
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- admin ---

// lockout hides the admin panel (404) from an IP after repeated failures,
// and from everyone after many failures overall. `nomax admin-code` resets it.
func (p *Panel) lockout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since := time.Now().Add(-time.Hour)
		ipN, _ := p.st.Failures(store.AdminLogin, ClientIP(r), since)
		allN, _ := p.st.Failures(store.AdminLogin, "", since)
		if ipN >= ipFailLimit || allN >= globalFailLimit {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Panel) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && p.st.ValidSession(c.Value)
}

func (p *Panel) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.loggedIn(r) {
			http.Redirect(w, r, p.admin, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	hash, err := p.st.Setting(AdminHashKey)
	code := strings.TrimSpace(r.PostFormValue("code"))
	if err != nil || hash == "" || code == "" || !CheckCode(code, hash) {
		p.st.RecordFailure(store.AdminLogin, ClientIP(r))
		p.log.Warn("admin login failed", "ip", ClientIP(r))
		w.WriteHeader(http.StatusUnauthorized)
		p.render(w, "login", map[string]any{"Cfg": p.cfg, "Admin": p.admin, "Error": "Wrong code."})
		return
	}
	token, err := p.st.CreateSession(sessionTTL)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, p.admin, http.StatusSeeOther)
}

func (p *Panel) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		p.st.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, p.admin, http.StatusSeeOther)
}

func (p *Panel) dashboard(w http.ResponseWriter, r *http.Request) {
	if !p.loggedIn(r) {
		p.render(w, "login", map[string]any{"Cfg": p.cfg, "Admin": p.admin})
		return
	}
	people, err := p.st.People()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	devices := 0
	for _, x := range people {
		devices += len(x.Devices)
	}
	p.render(w, "dashboard", map[string]any{
		"Cfg": p.cfg, "Admin": p.admin, "People": people, "Devices": devices,
		"Hysteria": p.vpn.HasHysteria(), "Uptime": time.Since(p.started).Round(time.Minute),
		"Flash": r.URL.Query().Get("m"), "Paused": p.enrollPaused(),
	})
}

func (p *Panel) addPerson(w http.ResponseWriter, r *http.Request) {
	max, _ := strconv.Atoi(r.PostFormValue("max"))
	person, err := p.st.CreatePerson(r.PostFormValue("name"), max)
	if err == nil {
		_, err = p.st.NewPIN(person.ID)
	}
	if err != nil {
		http.Redirect(w, r, p.admin+"?m="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, p.admin+"/people/"+strconv.FormatInt(person.ID, 10), http.StatusSeeOther)
}

func (p *Panel) invite(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	person, err := p.st.Person(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Cfg": p.cfg, "Admin": p.admin, "Person": person}
	if files, ok := secret(p.cfg.FilesPath); ok {
		data["FilesURL"] = "https://" + p.cfg.Host + files
	}
	if person.PIN != "" {
		link := "nomax://join?pin=" + person.PIN
		data["Link"] = link
		if c, err := qr.Encode(link, qr.M); err == nil {
			c.Scale = 6
			data["QR"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()))
		}
	}
	p.render(w, "invite", data)
}

func (p *Panel) resume(w http.ResponseWriter, r *http.Request) {
	p.st.ClearFailures(store.EnrollPIN)
	http.Redirect(w, r, p.admin, http.StatusSeeOther)
}

func (p *Panel) personAction(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var err error
	back := p.admin
	switch r.PathValue("action") {
	case "pin":
		_, err = p.st.NewPIN(id)
		back = p.admin + "/people/" + strconv.FormatInt(id, 10)
	case "disable":
		err = p.st.SetDisabled(id, true)
	case "enable":
		err = p.st.SetDisabled(id, false)
	case "delete":
		err = p.st.DeletePerson(id)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		back = p.admin + "?m=" + url.QueryEscape(err.Error())
	}
	p.kick()
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (p *Panel) deleteDeviceAdmin(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	back := p.admin
	if err := p.st.DeleteDevice(id); err != nil {
		back += "?m=" + url.QueryEscape(err.Error())
	}
	p.kick()
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "B"
}

// left renders a PIN's remaining lifetime; zero means permanent.
// formatPIN shows a PIN as the apps' boxes do: 123-456.
func formatPIN(pin string) string {
	if len(pin) != 6 {
		return pin
	}
	return pin[:3] + "-" + pin[3:]
}

func left(t time.Time) string {
	if t.IsZero() {
		return "permanent"
	}
	m := int(time.Until(t).Round(time.Minute).Minutes())
	if m < 1 {
		return "under a minute left"
	}
	return strconv.Itoa(m) + " min left"
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	}
}
