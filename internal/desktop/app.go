package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/apiclient"
	conncheck "github.com/ginzlabs/nomaxvpn/internal/check"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Engine is the core: nomaxcore on Windows, a stand-in in the preview.
type Engine interface {
	Start(profileJSON, protocol, route, preferred, wgKey string, tunFd int32, endpointIP string) (string, error)
	Cancel()
	Stop()
	Events(since int64) string
	Stats() string
	// Endpoint is the server's address from the profile, "" if none.
	Endpoint(profileJSON string) string
	// Preferred is the order Auto has learned, which the next Start takes.
	Preferred() string
}

// Platform is what the window's system does for the app.
type Platform struct {
	// Info is "NoMax 1.0 (5) · PC-NAME, Windows 11", for what gets shared.
	Info string
	// Version is "1.0.0 (5)", for the screens.
	Version string
	// DeviceName is the name the server lists the device under.
	DeviceName string
	// Copy puts text on the clipboard.
	Copy func(string) error
	// Reveal shows a saved file in the file manager.
	Reveal func(path string) error
	// Minimize and Close act on the window; Close disconnects first.
	Minimize, Close func()
	// Client makes the app's requests: the server's API and the IP check. Nil is the default.
	Client *http.Client
}

// App is the Windows app's state and actions. Its methods are what the page calls.
type App struct {
	host     string
	store    Store
	engine   Engine
	platform Platform
	log      *Log
	trace    string // where the IP check asks; Cloudflare's trace page

	mu       sync.Mutex
	device   *Device
	settings Settings
	joining  bool
	err      string
	tunnel   string // off, connecting, on
	// conns counts Connects and Disconnects, so a start that finishes after
	// either knows it was overtaken.
	conns    int
	active   string
	since    time.Time
	rx, tx   int64
	run      *Run
	runShown bool
	// reconnect is the run the core began to replace a stalled tunnel.
	reconnect int64
	lastSeq   int64
	ip        *IPResult
	checking  bool
	ipGen     int
	send      SendState
}

// IPResult is what Cloudflare's trace page says websites see.
type IPResult struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Colo    string `json:"colo"`
}

// New loads the saved device and starts following the core's steps.
func New(host string, store Store, engine Engine, platform Platform) *App {
	a := &App{host: host, store: store, engine: engine, platform: platform, tunnel: "off",
		log: openLog(filepath.Join(store.Dir, "log.jsonl")), trace: "https://1.1.1.1/cdn-cgi/trace"}
	os.MkdirAll(store.Dir, 0o700)
	d, err := store.Device()
	if err != nil {
		a.log.app("The saved device is unreadable: " + err.Error())
	}
	a.device = d
	a.settings = store.Settings()
	if a.settings.Protocol == "" {
		a.settings.Protocol = "auto"
	}
	if a.settings.Route == "" {
		a.settings.Route = "auto"
	}
	go a.follow()
	go func() {
		// The app stays in the tray for days; the profile may gain relays or addresses meanwhile.
		for ; ; time.Sleep(6 * time.Hour) {
			a.refreshProfile()
		}
	}()
	go a.checkIP(0)
	go a.retrySend()
	return a
}

// follow takes the core's new steps into the log and the run card.
func (a *App) follow() {
	for range time.Tick(300 * time.Millisecond) {
		a.poll()
	}
}

func (a *App) poll() {
	a.mu.Lock()
	since, on := a.lastSeq, a.tunnel == "on"
	a.mu.Unlock()
	if on {
		var st struct{ RX, TX int64 }
		json.Unmarshal([]byte(a.engine.Stats()), &st)
		a.mu.Lock()
		a.rx, a.tx = st.RX, st.TX
		a.mu.Unlock()
	}
	var events []Event
	if json.Unmarshal([]byte(a.engine.Events(since)), &events) != nil || len(events) == 0 {
		return
	}
	a.mu.Lock()
	var lines []LogLine
	reconnected := false
	for _, e := range events {
		if e.Seq <= a.lastSeq {
			continue
		}
		a.lastSeq = e.Seq
		if e.State == "start" {
			a.run, a.runShown = startRun(e), true
		} else if a.run != nil {
			a.run.apply(e)
		}
		switch {
		case e.State == "start" && e.Reconnect && a.tunnel != "off":
			a.tunnel, a.active, a.reconnect = "connecting", "", e.Run
		case e.State == "done" && e.Run == a.reconnect && e.Proto != "" && a.tunnel == "connecting":
			a.tunnel, a.active, a.since, a.rx, a.tx, a.err = "on", e.Proto, time.Now(), 0, 0, ""
			if a.run != nil && a.run.ID == e.Run && a.run.Kind == "auto" {
				a.settings.LastGood = a.engine.Preferred()
				a.store.SaveSettings(a.settings)
			}
			reconnected = true
		case e.State == "done" && e.Proto == "" && a.tunnel == "on" && a.run != nil && a.run.ID == e.Run && a.run.Kind == "single":
			// A protocol picked by hand stays on when its traffic check fails.
			a.err = noTraffic(a.active)
		}
		lines = append(lines, LogLine{T: e.T, Run: e.Run, Proto: e.Proto, State: e.State, Step: e.Step})
	}
	a.mu.Unlock()
	a.log.add(lines...)
	if reconnected {
		go a.checkIP(time.Second)
	}
}

// noTraffic is what the home screen says when a picked protocol connects but carries nothing.
func noTraffic(proto string) string {
	return Title(proto) + " is on, but nothing comes through it. Try Auto, or another protocol."
}

func (a *App) logApp(format string, args ...any) { a.log.app(fmt.Sprintf(format, args...)) }

// api is the device API at host, through the relays the profile lists (or
// the ones built in), first when the route goes through a relay.
func (a *App) api(host string) API {
	a.mu.Lock()
	defer a.mu.Unlock()
	var relays []string
	for _, r := range a.profileLocked().Relays {
		relays = append(relays, r.Address)
	}
	return API{Host: host, Relays: relays, RelayFirst: a.settings.Route == "relay" || a.settings.Route == "exit", Client: a.platform.Client}
}

func (a *App) profileLocked() profile.Profile {
	var p profile.Profile
	if a.device != nil {
		json.Unmarshal(a.device.Profile, &p)
	}
	return p
}

// serverHost is the server's name: the profile's, which follows the server
// when it moves, else the one joined.
func (d Device) serverHost() string {
	var p struct {
		Host string `json:"host"`
	}
	if json.Unmarshal(d.Profile, &p) == nil && p.Host != "" {
		return p.Host
	}
	return d.Host
}

func (a *App) setError(msg string) {
	a.mu.Lock()
	changed := msg != "" && msg != a.err
	a.err = msg
	a.mu.Unlock()
	if changed {
		a.logApp("Error: %s", msg)
	}
}

// State is everything the page shows, as it is now.
type State struct {
	Joined    bool      `json:"joined"`
	Host      string    `json:"host"`
	Joining   bool      `json:"joining"`
	Error     string    `json:"error"`
	Tunnel    string    `json:"tunnel"`
	Active    string    `json:"active"`
	Choice    string    `json:"choice"`
	Protocols []Choice  `json:"protocols"`
	Route     string    `json:"route"`
	Routes    []Choice  `json:"routes"`
	Since     int64     `json:"since"`
	RX        int64     `json:"rx"`
	TX        int64     `json:"tx"`
	IP        *IPResult `json:"ip"`
	Checking  bool      `json:"checkingIP"`
	Run       *Run      `json:"run"`
	App       string    `json:"app"`
	Version   string    `json:"version"`
	Send      SendState `json:"send"`
}

type Choice struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (a *App) State() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := State{Joined: a.device != nil, Host: a.host, Joining: a.joining, Error: a.err, Tunnel: a.tunnel,
		Active: a.active, Choice: a.settings.Protocol, IP: a.ip, Checking: a.checking, App: a.platform.Info, Version: a.platform.Version, Send: a.send}
	if a.device != nil {
		s.Host = a.device.serverHost()
	}
	s.Protocols = a.protocolsLocked()
	s.Route, s.Routes = a.settings.Route, a.routesLocked()
	s.Send.Pending = a.settings.ReportPending
	if a.tunnel == "on" {
		s.Since, s.RX, s.TX = a.since.UnixMilli(), a.rx, a.tx
	}
	if a.runShown && a.run != nil {
		r := *a.run
		r.Rows = slices.Clone(a.run.Rows)
		s.Run = &r
	}
	return s
}

// protocolsLocked is Auto and what the server offers on the chosen route, in
// the order Auto tries them. The exit route has only Xray's protocols.
func (a *App) protocolsLocked() []Choice {
	out := []Choice{{"auto", "Auto"}}
	p := a.profileLocked()
	if a.settings.Route == "exit" {
		if q, ok := p.WithExit(); ok {
			p = q
		}
	}
	for _, id := range profile.Protocols {
		if a.device == nil || profile.Offered(p, id) {
			out = append(out, Choice{id, Title(id)})
		}
	}
	return out
}

// routesLocked are the ways to the server this device has.
func (a *App) routesLocked() []Choice {
	out := []Choice{{"auto", "Auto"}, {"direct", "Direct"}}
	p := a.profileLocked()
	if len(p.Relays) > 0 || (a.device == nil && apiclient.Relays != "") {
		out = append(out, Choice{"relay", "Via relay"})
	}
	if p.Exit != nil {
		out = append(out, Choice{"exit", "Relay exit"})
	}
	return out
}

// Join enrolls this computer with a PIN.
func (a *App) Join(pin string) {
	a.mu.Lock()
	if a.joining || a.device != nil {
		a.mu.Unlock()
		return
	}
	a.joining, a.err = true, ""
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.joining = false
		a.mu.Unlock()
	}()
	key := profile.NewWireGuardKey()
	pub, err := profile.WireGuardPublic(key)
	if err != nil {
		a.setError(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, prof, err := a.api(a.host).Enroll(ctx, strings.TrimSpace(pin), a.platform.DeviceName, pub)
	if err != nil {
		a.setError(firstLine(err))
		return
	}
	d := Device{Host: a.host, Token: token, WGKey: key, Profile: prof}
	if err := a.store.SaveDevice(d); err != nil {
		a.setError("Couldn't save the device: " + err.Error())
		return
	}
	a.mu.Lock()
	a.device = &d
	a.mu.Unlock()
	a.logApp("Joined %s as %s", a.host, a.platform.DeviceName)
}

// refreshProfile fetches the profile again, as the server may offer more since.
func (a *App) refreshProfile() {
	a.mu.Lock()
	d := a.device
	a.mu.Unlock()
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := a.api(d.serverHost()).Profile(ctx, d.Token)
	var apiErr *APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.Unauthorized:
		a.forget()
		a.setError(apiErr.Msg)
		return
	case err != nil:
		a.logApp("Couldn't refresh the profile: %s", firstLine(err))
		return
	}
	if sameJSON(p, d.Profile) {
		return
	}
	updated := *d
	updated.Profile = p
	a.store.SaveDevice(updated)
	a.mu.Lock()
	a.device = &updated
	routeOffered := slices.ContainsFunc(a.routesLocked(), func(c Choice) bool { return c.ID == a.settings.Route })
	if !routeOffered {
		a.settings.Route = "auto"
		a.store.SaveSettings(a.settings)
	}
	offered := slices.ContainsFunc(a.protocolsLocked(), func(c Choice) bool { return c.ID == a.settings.Protocol })
	a.mu.Unlock()
	a.logApp("Profile updated")
	if !offered {
		a.Choose("auto")
	}
}

func sameJSON(a, b []byte) bool {
	var ca, cb bytes.Buffer
	return json.Compact(&ca, a) == nil && json.Compact(&cb, b) == nil && bytes.Equal(ca.Bytes(), cb.Bytes())
}

// Connect starts the tunnel with the chosen protocol; Test tries every one.
func (a *App) Connect(test bool) {
	a.mu.Lock()
	d := a.device
	choice := a.settings.Protocol
	if test {
		choice = Test
		if a.settings.Protocol != "auto" {
			a.settings.Protocol = "auto"
			a.store.SaveSettings(a.settings)
		}
	}
	if d == nil {
		a.mu.Unlock()
		return
	}
	a.tunnel, a.err, a.active, a.runShown = "connecting", "", "", false
	a.conns++
	conn := a.conns
	a.ipGen++
	a.ip, a.checking = nil, true
	preferred, route := a.settings.LastGood, a.settings.Route
	a.mu.Unlock()
	where := ""
	if route != "auto" {
		where = ", " + routeTitle(route)
	}
	if test {
		a.logApp("Test every protocol%s", where)
	} else {
		a.logApp("Connect with %s%s", Title(choice), where)
	}
	go a.up(*d, choice, route, preferred, conn)
}

func routeTitle(id string) string {
	switch id {
	case "direct":
		return "Direct"
	case "relay":
		return "Via relay"
	case "exit":
		return "Relay exit"
	}
	return "Auto"
}

// overtaken says whether a Connect or Disconnect came after Connect number
// conn, and whether the tunnel is off.
func (a *App) overtaken(conn int) (overtaken, off bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conns != conn, a.tunnel == "off"
}

func (a *App) up(d Device, choice, route, preferred string, conn int) {
	endpoint := a.engine.Endpoint(string(d.Profile))
	if late, _ := a.overtaken(conn); late {
		// A Disconnect before the core's run began had nothing to cancel.
		return
	}
	if endpoint == "" {
		a.down()
		a.setError("Can't find " + d.serverHost() + ".")
		return
	}
	used, err := a.engine.Start(string(d.Profile), choice, route, preferred, d.WGKey, -1, endpoint)
	if choice == "auto" || choice == Test {
		a.mu.Lock()
		a.settings.LastGood = a.engine.Preferred()
		a.store.SaveSettings(a.settings)
		a.mu.Unlock()
	}
	if late, off := a.overtaken(conn); late || off {
		// The Disconnect's Stop may have run before this Start took the lock.
		if err == nil && off {
			a.engine.Stop()
		}
		return
	}
	if err != nil {
		if err.Error() == "Stopped" {
			return
		}
		a.down()
		a.setError(firstLine(err))
		return
	}
	a.mu.Lock()
	a.tunnel, a.active, a.since, a.rx, a.tx = "on", used, time.Now(), 0, 0
	a.mu.Unlock()
	a.sendIfPending()
	a.checkIP(time.Second)
}

func (a *App) down() {
	a.engine.Stop()
	a.mu.Lock()
	wasOn := a.tunnel != "off"
	a.tunnel, a.active = "off", ""
	a.mu.Unlock()
	if wasOn {
		a.checkIP(time.Second)
	}
}

// Connected says whether the tunnel is on or connecting.
func (a *App) Connected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunnel != "off"
}

// Disconnect stops the tunnel, or the run that's connecting.
func (a *App) Disconnect() {
	a.mu.Lock()
	if a.run != nil && !a.run.Finished {
		a.runShown = false
	}
	a.err = ""
	a.conns++
	a.mu.Unlock()
	a.logApp("Disconnect")
	a.engine.Cancel()
	a.down()
}

// Choose picks a protocol, reconnecting with it when the tunnel is up.
func (a *App) Choose(id string) {
	a.mu.Lock()
	a.settings.Protocol = id
	a.store.SaveSettings(a.settings)
	on := a.tunnel != "off"
	a.mu.Unlock()
	if on {
		a.engine.Cancel()
		a.Connect(false)
	}
}

// ChooseRoute picks the way to the server, reconnecting when the tunnel is
// up. A protocol the route doesn't have goes back to Auto.
func (a *App) ChooseRoute(id string) {
	a.mu.Lock()
	a.settings.Route = id
	if !slices.ContainsFunc(a.protocolsLocked(), func(c Choice) bool { return c.ID == a.settings.Protocol }) {
		a.settings.Protocol = "auto"
	}
	a.store.SaveSettings(a.settings)
	on := a.tunnel != "off"
	a.mu.Unlock()
	if on {
		a.engine.Cancel()
		a.Connect(false)
	}
}

// CloseRun hides the run card until the next run.
func (a *App) CloseRun() {
	a.mu.Lock()
	a.runShown = false
	a.mu.Unlock()
}

// Leave removes this computer from the server and forgets it.
func (a *App) Leave() {
	a.mu.Lock()
	d := a.device
	a.mu.Unlock()
	if d == nil {
		return
	}
	a.Disconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a.api(d.serverHost()).DeleteDevice(ctx, d.Token)
	a.forget()
	a.logApp("Removed this device")
}

func (a *App) forget() {
	a.engine.Stop()
	a.store.ForgetDevice()
	a.mu.Lock()
	a.device, a.tunnel, a.active = nil, "off", ""
	a.mu.Unlock()
}

// CheckIP asks again what websites see.
func (a *App) CheckIP() { go a.checkIP(0) }

// checkIP asks Cloudflare after delay. The app's own traffic goes through the
// tunnel like everything else's, so the answer is what websites see.
func (a *App) checkIP(delay time.Duration) {
	a.mu.Lock()
	a.ipGen++
	gen := a.ipGen
	a.ip, a.checking = nil, true
	a.mu.Unlock()
	time.Sleep(delay)
	r := fetchTrace(a.platform.Client, a.trace)
	a.mu.Lock()
	defer a.mu.Unlock()
	if gen != a.ipGen {
		return
	}
	a.ip, a.checking = r, false
}

// fetchTrace asks on a new connection each time: one kept alive from before
// the tunnel came up (or went down) would still take the old way.
func fetchTrace(c *http.Client, url string) *IPResult {
	if c == nil {
		c = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	r := parseTrace(string(b))
	if r.IP == "" {
		return nil
	}
	return &r
}

func parseTrace(text string) IPResult {
	var r IPResult
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			r.IP = v
		case "loc":
			r.Country = v
		case "colo":
			r.Colo = v
		}
	}
	return r
}

// Logs are the log's sections, newest first.
func (a *App) Logs() []Section { return sections(a.log.snapshot()) }

// LogText is the log as text to share.
func (a *App) LogText() string {
	a.mu.Lock()
	choice, route := a.settings.Protocol, a.settings.Route
	a.mu.Unlock()
	return logText(a.platform.Info+" · protocol "+Title(choice)+" · route "+routeTitle(route), a.log.snapshot())
}

func (a *App) ClearLog() { a.log.clear() }

// CheckStart begins a connection check against the server.
func (a *App) CheckStart() {
	a.logApp("Connection check started")
	conncheck.Start(a.State().Host, a.platform.Info)
	go func() {
		for range time.Tick(300 * time.Millisecond) {
			var s struct {
				Done    bool   `json:"done"`
				Verdict string `json:"verdict"`
			}
			if json.Unmarshal([]byte(conncheck.State()), &s) != nil {
				return
			}
			if s.Done {
				a.logApp("Connection check: %s", s.Verdict)
				a.keepCheck()
				return
			}
		}
	}()
}

// CheckState is the check as nomaxcheck reports it.
func (a *App) CheckState() json.RawMessage { return json.RawMessage(conncheck.State()) }

func (a *App) CheckText() string { return conncheck.Text() }

func (a *App) CheckCancel() { conncheck.Cancel() }

// Copy puts text on the clipboard.
func (a *App) Copy(text string) error {
	if a.platform.Copy == nil {
		return errors.New("no clipboard here")
	}
	return a.platform.Copy(text)
}

// Save writes text to the Downloads folder and shows it there.
func (a *App) Save(name, text string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Downloads")
	if _, err := os.Stat(dir); err != nil {
		dir = home
	}
	path := filepath.Join(dir, fmt.Sprintf("%s %s.txt", name, time.Now().Format("2006-01-02 1504")))
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return "", err
	}
	if a.platform.Reveal != nil {
		a.platform.Reveal(path)
	}
	return path, nil
}

// Quit stops the tunnel, for when the window closes.
func (a *App) Quit() {
	a.engine.Cancel()
	a.engine.Stop()
	conncheck.Cancel()
}
