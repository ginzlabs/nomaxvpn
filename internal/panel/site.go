package panel

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// The pages' stylesheet is inlined and allowed by its hash, so the site has
// no stylesheet URL to find.
var style, styleHash = func() (string, string) {
	b, _ := web.ReadFile("web/style.css")
	return string(b), cspHash(string(b))
}()

// The home page is the whole public site. Its inline style and script are
// allowed by their hashes and nothing else is.
var homePage, homeCSP = func() (string, string) {
	b, _ := web.ReadFile("web/home/index.html")
	page := string(b)
	return page, "default-src 'none'; script-src " + cspHash(between(page, "<script>", "</script>")) +
		"; style-src " + cspHash(between(page, "<style>", "</style>")) +
		"; img-src data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
}()

func between(s, open, close string) string {
	_, s, _ = strings.Cut(s, open)
	s, _, _ = strings.Cut(s, close)
	return s
}

func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// label is the domain's first label, which names the downloads and the home
// page.
func (p *Panel) label() string {
	name, _, _ := strings.Cut(strings.ToLower(p.cfg.Host), ".")
	if name == "" {
		return "app"
	}
	return name
}

func (p *Panel) apkName() string { return p.label() + ".apk" }
func (p *Panel) exeName() string { return p.label() + "-setup.exe" }

func (p *Panel) home(w http.ResponseWriter, r *http.Request) {
	title := p.label()
	title = strings.ToUpper(title[:1]) + title[1:]
	w.Header().Set("Content-Security-Policy", homeCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strings.Replace(homePage, "<title>TITLE</title>", "<title>"+title+"</title>", 1)))
}

// secret is a secret path's route, when it's long enough to serve.
func secret(path string) (string, bool) {
	path = strings.Trim(path, "/")
	return "/" + path, len(path) >= 8
}

// legacy serves a device route on the old public API path, for apps built
// before the secret one. Anything that isn't an enrolled device gets the
// same 404 as an unknown path.
func (p *Panel) legacy(next func(http.ResponseWriter, *http.Request, store.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		dev, err := p.st.DeviceByToken(token)
		if token == "" || err != nil {
			http.NotFound(w, r)
			return
		}
		next(w, r, dev)
	}
}
