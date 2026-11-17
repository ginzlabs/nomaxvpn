// Package check looks at how a network treats the NoMax server, for people who
// can't connect: their own connection, DNS, the server's address and ports, the
// route through Cloudflare, and a few other sites. It uses no credentials, so
// the report is safe to send to whoever runs the server.
package check

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/quic-go"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// The server's TCP ports besides 443, as internal/vpn opens them: Reality Mux,
// AnyTLS and Mieru.
var otherPorts = []int{2053, 2083, 2096}

// Step states.
const (
	Waiting = "waiting"
	Running = "running"
	OK      = "ok"
	Fail    = "fail"
	Info    = "info"
)

const (
	stepWait     = 6 * time.Second
	downloadWait = 10 * time.Second
	downloadSize = 64 << 10
	// serverGap spaces connections to the server, as the tunnel does: some
	// filters block addresses that see several TLS handshakes at once.
	serverGap = time.Second
	// otherName is a name the server doesn't serve, to tell a blocked name from
	// a blocked address.
	otherName = "example.com"
)

// Step is one line of the report.
type Step struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	MS     int64  `json:"ms,omitempty"`
}

// Report is a check, finished or in progress.
type Report struct {
	Host    string `json:"host"`
	App     string `json:"app,omitempty"`
	Started int64  `json:"started"` // Unix milliseconds
	Done    bool   `json:"done"`
	Verdict string `json:"verdict,omitempty"`
	Steps   []Step `json:"steps"`
}

var plan = []Step{
	{ID: "network", Group: "Your connection", Title: "Your network"},
	{ID: "dns", Group: "DNS", Title: "Your network's DNS"},
	{ID: "dns.cloudflare", Group: "DNS", Title: "Cloudflare DNS"},
	{ID: "dns.google", Group: "DNS", Title: "Google DNS"},
	{ID: "tcp", Group: "Our server", Title: "Address (IPv4)"},
	{ID: "tls", Group: "Our server", Title: "Secure connection"},
	{ID: "download", Group: "Our server", Title: "64 KB download"},
	{ID: "tls.other", Group: "Our server", Title: "Under another name"},
	{ID: "tcp6", Group: "Our server", Title: "Address (IPv6)"},
	{ID: "ports", Group: "Our server", Title: "Other ports"},
	{ID: "udp", Group: "Our server", Title: "UDP"},
	{ID: "web", Group: "Through Cloudflare", Title: "Website"},
	{ID: "web.download", Group: "Through Cloudflare", Title: "64 KB download"},
	{ID: "apple", Group: "Other sites", Title: "apple.com"},
	{ID: "yandex", Group: "Other sites", Title: "ya.ru"},
	{ID: "upcloud", Group: "Other sites", Title: "Another UpCloud server"},
}

var (
	mu      sync.Mutex
	current *run
	stop    context.CancelFunc
)

// Start begins a check of host, replacing one in progress. app names the app
// and device for the report.
func Start(host, app string) {
	mu.Lock()
	defer mu.Unlock()
	if stop != nil {
		stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	stop = cancel
	r := &run{rep: Report{Host: host, App: app, Started: time.Now().UnixMilli(), Steps: slices.Clone(plan)}}
	for i := range r.rep.Steps {
		r.rep.Steps[i].State = Waiting
	}
	current = r
	go func() {
		r.run(ctx)
		cancel()
	}()
}

// Cancel stops the check in progress; its report says what it got to.
func Cancel() {
	mu.Lock()
	defer mu.Unlock()
	if stop != nil {
		stop()
	}
}

// State is the latest report as JSON, or {} before the first check.
func State() string {
	r := latest()
	if r == nil {
		return "{}"
	}
	b, _ := json.Marshal(r.report())
	return string(b)
}

// Text is the latest report as plain text for sharing.
func Text() string {
	r := latest()
	if r == nil {
		return ""
	}
	return r.report().Text()
}

func latest() *run {
	mu.Lock()
	defer mu.Unlock()
	return current
}

type run struct {
	mu  sync.Mutex
	rep Report
}

func (r *run) report() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := r.rep
	rep.Steps = slices.Clone(r.rep.Steps)
	return rep
}

func (r *run) set(id, state, detail string, took time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rep.Steps {
		if r.rep.Steps[i].ID == id {
			r.rep.Steps[i].State, r.rep.Steps[i].Detail, r.rep.Steps[i].MS = state, detail, took.Milliseconds()
		}
	}
}

// do runs step id: f returns its state and detail.
func (r *run) do(id string, f func() (string, string)) string {
	r.set(id, Running, "", 0)
	t := time.Now()
	state, detail := f()
	r.set(id, state, detail, time.Since(t))
	return state
}

func (r *run) run(ctx context.Context) {
	host := r.rep.Host
	var wg sync.WaitGroup
	for _, f := range []func(){
		func() { r.network(ctx) },
		func() { r.server(ctx, r.dns(ctx, host)) },
		func() { r.web(ctx, "web."+host) },
		func() {
			r.do("apple", func() (string, string) { return page(ctx, "https://www.apple.com/library/test/success.html") })
		},
		func() { r.do("yandex", func() (string, string) { return page(ctx, "https://ya.ru/") }) },
		func() {
			r.do("upcloud", func() (string, string) { return reach(ctx, "tcp", "api.upcloud.com:443") })
		},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rep.Steps {
		if s := &r.rep.Steps[i]; s.State == Waiting || s.State == Running {
			s.State, s.Detail = Fail, "Stopped"
		}
	}
	r.rep.Verdict = verdict(r.rep)
	r.rep.Done = true
}

// network finds the device's public address and provider.
func (r *run) network(ctx context.Context) {
	r.do("network", func() (string, string) {
		var meta struct {
			IP      string `json:"clientIp"`
			ASN     int    `json:"asn"`
			Org     string `json:"asOrganization"`
			Country string `json:"country"`
		}
		speed := http.Header{"Referer": {"https://speed.cloudflare.com/"}}
		if err := getJSON(ctx, "https://speed.cloudflare.com/meta", speed, &meta); err == nil && meta.IP != "" {
			return Info, fmt.Sprintf("%s (AS%d), %s · %s", meta.Org, meta.ASN, meta.Country, meta.IP)
		}
		var info struct {
			IP      string `json:"ip"`
			Org     string `json:"org"`
			Country string `json:"country"`
		}
		if err := getJSON(ctx, "https://ipinfo.io/json", nil, &info); err != nil {
			return Fail, "Couldn't find out: " + reason(err)
		}
		return Info, fmt.Sprintf("%s, %s · %s", info.Org, info.Country, info.IP)
	})
}

type addrs struct{ v4, v6 []netip.Addr }

// dns looks host up through the system and through encrypted DNS, and returns
// the server's addresses, trusting encrypted DNS over the system's.
func (r *run) dns(ctx context.Context, host string) addrs {
	var system, cf, google []netip.Addr
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		cf = r.doh(ctx, "dns.cloudflare", "https://1.1.1.1/dns-query?name=%s&type=%s", host)
	}()
	go func() {
		defer wg.Done()
		google = r.doh(ctx, "dns.google", "https://8.8.8.8/resolve?name=%s&type=%s", host)
	}()
	var systemErr error
	t := time.Now()
	r.set("dns", Running, "", 0)
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, stepWait)
		defer cancel()
		system, systemErr = net.DefaultResolver.LookupNetIP(c, "ip", host)
		for i := range system {
			system[i] = system[i].Unmap()
		}
	}()
	wg.Wait()
	truth := union(cf, google)
	switch {
	case systemErr != nil:
		r.set("dns", Fail, reason(systemErr), time.Since(t))
	case len(truth) > 0 && !overlaps(system, truth):
		r.set("dns", Fail, "Gives "+list(system)+", encrypted DNS gives "+list(truth), time.Since(t))
	default:
		r.set("dns", OK, list(system), time.Since(t))
	}
	use := truth
	if len(use) == 0 {
		use = system
	}
	var a addrs
	for _, ip := range use {
		if ip.Is4() {
			a.v4 = append(a.v4, ip)
		} else {
			a.v6 = append(a.v6, ip)
		}
	}
	return a
}

// doh asks a DNS-over-HTTPS JSON API for host's A and AAAA records.
func (r *run) doh(ctx context.Context, id, format, host string) []netip.Addr {
	var out []netip.Addr
	r.do(id, func() (string, string) {
		var errs []error
		for _, typ := range []string{"A", "AAAA"} {
			var resp struct {
				Status int
				Answer []struct {
					Type int
					Data string
				}
			}
			dnsJSON := http.Header{"Accept": {"application/dns-json"}}
			if err := getJSON(ctx, fmt.Sprintf(format, url.QueryEscape(host), typ), dnsJSON, &resp); err != nil {
				errs = append(errs, err)
				continue
			}
			for _, a := range resp.Answer {
				if ip, err := netip.ParseAddr(a.Data); err == nil && (a.Type == 1 || a.Type == 28) {
					out = append(out, ip.Unmap())
				}
			}
		}
		if len(errs) == 2 {
			return Fail, reason(errs[0])
		}
		if len(out) == 0 {
			return Fail, "No address"
		}
		return OK, list(out)
	})
	return out
}

// server tries the server's address, one connection at a time.
func (r *run) server(ctx context.Context, a addrs) {
	host := r.rep.Host
	if len(a.v4) == 0 && len(a.v6) == 0 {
		for _, id := range []string{"tcp", "tls", "download", "tls.other", "tcp6", "ports", "udp"} {
			r.set(id, Fail, "No address for "+host, 0)
		}
		return
	}
	ip := append(a.v4, a.v6...)[0]
	addr := func(port int) string { return net.JoinHostPort(ip.String(), strconv.Itoa(port)) }
	gap := func() bool { return sleep(ctx, serverGap) }

	reached := r.do("tcp", func() (string, string) {
		if len(a.v4) == 0 {
			return Info, "No IPv4 address"
		}
		return reach(ctx, "tcp", addr(443))
	}) != Fail
	if reached {
		r.do("tls", func() (string, string) { return handshake(ctx, addr(443), host, false) })
		gap()
		r.do("download", func() (string, string) {
			return download(ctx, httpsVia(addr(443), host), "https://"+host+profile.API()+"/check?bytes="+strconv.Itoa(downloadSize))
		})
		gap()
		r.do("tls.other", func() (string, string) { return handshake(ctx, addr(443), otherName, true) })
	} else {
		for _, id := range []string{"tls", "download", "tls.other"} {
			r.set(id, Fail, "Skipped: the address can't be reached", 0)
		}
	}
	r.do("tcp6", func() (string, string) {
		if len(a.v6) == 0 {
			return Info, "No IPv6 address"
		}
		state, detail := reach(ctx, "tcp6", net.JoinHostPort(a.v6[0].String(), "443"))
		if state == Fail {
			if s, _ := reach(ctx, "tcp6", "[2606:4700:4700::1111]:443"); s == Fail {
				return Info, "This network has no IPv6"
			}
		}
		return state, detail
	})
	r.do("ports", func() (string, string) {
		var parts []string
		bad := 0
		for _, p := range otherPorts {
			if s, _ := reach(ctx, "tcp", addr(p)); s == OK {
				parts = append(parts, fmt.Sprintf("%d open", p))
			} else {
				parts = append(parts, fmt.Sprintf("%d blocked", p))
				bad++
			}
		}
		if bad > 0 {
			return Fail, strings.Join(parts, ", ")
		}
		return OK, strings.Join(parts, ", ")
	})
	gap()
	r.do("udp", func() (string, string) { return quicHandshake(ctx, addr(443), host) })
}

// web loads the website and the download through Cloudflare's proxy.
func (r *run) web(ctx context.Context, name string) {
	if r.do("web", func() (string, string) { return page(ctx, "https://"+name+"/") }) == Fail {
		r.set("web.download", Fail, "Skipped: the website didn't load", 0)
		return
	}
	r.do("web.download", func() (string, string) {
		return download(ctx, client(), "https://"+name+profile.API()+"/check?bytes="+strconv.Itoa(downloadSize))
	})
}

func reach(ctx context.Context, network, addr string) (string, string) {
	c, cancel := context.WithTimeout(ctx, stepWait)
	defer cancel()
	t := time.Now()
	conn, err := (&net.Dialer{}).DialContext(c, network, addr)
	if err != nil {
		return Fail, reason(err)
	}
	conn.Close()
	return OK, "Connected in " + ms(time.Since(t))
}

// handshake opens TLS to addr as name. With anyAnswer, the server answering at
// all counts, even to refuse the name.
func handshake(ctx context.Context, addr, name string, anyAnswer bool) (string, string) {
	c, cancel := context.WithTimeout(ctx, stepWait)
	defer cancel()
	t := time.Now()
	d := tls.Dialer{Config: &tls.Config{ServerName: name, InsecureSkipVerify: anyAnswer}}
	conn, err := d.DialContext(c, "tcp", addr)
	if err != nil {
		if anyAnswer && refused(err) {
			return OK, "The server answered in " + ms(time.Since(t))
		}
		return Fail, reason(err)
	}
	conn.Close()
	return OK, "Done in " + ms(time.Since(t))
}

// quicHandshake proves UDP reaches the server: Hysteria2 answers QUIC on 443.
func quicHandshake(ctx context.Context, addr, name string) (string, string) {
	c, cancel := context.WithTimeout(ctx, stepWait)
	defer cancel()
	t := time.Now()
	conn, err := quic.DialAddr(c, addr, &tls.Config{ServerName: name, NextProtos: []string{"h3"}, InsecureSkipVerify: true},
		&quic.Config{HandshakeIdleTimeout: stepWait})
	if err != nil {
		return Fail, reason(err)
	}
	conn.CloseWithError(0, "")
	return OK, "QUIC answered in " + ms(time.Since(t))
}

// page loads url; any HTTP answer counts.
func page(ctx context.Context, url string) (string, string) {
	c, cancel := context.WithTimeout(ctx, stepWait)
	defer cancel()
	t := time.Now()
	req, _ := http.NewRequestWithContext(c, "GET", url, nil)
	resp, err := client().Do(req)
	if err != nil {
		return Fail, reason(err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return OK, "Loaded in " + ms(time.Since(t))
}

// download fetches url and reports how far it got: some filters let a
// connection carry a few kilobytes and then stall it.
func download(ctx context.Context, cl *http.Client, url string) (string, string) {
	c, cancel := context.WithTimeout(ctx, downloadWait)
	defer cancel()
	t := time.Now()
	req, _ := http.NewRequestWithContext(c, "GET", url, nil)
	resp, err := cl.Do(req)
	if err != nil {
		return Fail, reason(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Fail, "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return Fail, fmt.Sprintf("Stopped after %d KB: %s", n>>10, reason(err))
	}
	return OK, fmt.Sprintf("%d KB in %s", n>>10, ms(time.Since(t)))
}

func client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: stepWait},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpsVia is a client that reaches name at addr, whatever DNS says.
func httpsVia(addr, name string) *http.Client {
	t := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: stepWait,
		TLSClientConfig:     &tls.Config{ServerName: name},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: t}
}

func getJSON(ctx context.Context, url string, header http.Header, v any) error {
	c, cancel := context.WithTimeout(ctx, stepWait)
	defer cancel()
	req, _ := http.NewRequestWithContext(c, "GET", url, nil)
	maps.Copy(req.Header, header)
	resp, err := client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("HTTP " + strconv.Itoa(resp.StatusCode))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(v)
}

// reason says in a few words why a connection failed.
func reason(err error) string {
	var ne net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "No answer (timed out)"
	case errors.Is(err, context.Canceled):
		return "Stopped"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "Refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "Connection reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "Network unreachable"
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "Name not found"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "Connection closed"
	case refused(err):
		s := err.Error()
		return "Refused by the server (" + s[strings.LastIndex(s, ": ")+2:] + ")"
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return "Wrong certificate, someone may be intercepting: " + cert.Err.Error()
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

// refused reports a TLS alert from the other side: crypto/tls returns it as a
// "remote error", QUIC as an AlertError.
func refused(err error) bool {
	var op *net.OpError
	var alert tls.AlertError
	return errors.As(err, &op) && op.Op == "remote error" || errors.As(err, &alert)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) + " ms" }

func list(ips []netip.Addr) string {
	if len(ips) == 0 {
		return "no address"
	}
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return strings.Join(s, ", ")
}

func union(a, b []netip.Addr) []netip.Addr {
	out := slices.Clone(a)
	for _, ip := range b {
		if !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	return out
}

func overlaps(a, b []netip.Addr) bool {
	for _, ip := range a {
		if slices.Contains(b, ip) {
			return true
		}
	}
	return false
}
