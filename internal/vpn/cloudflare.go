package vpn

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// CloudflareAddr is Xray's VLESS over WebSocket, on the loopback only: the
// website hands it the WebSocket connections Cloudflare carries.
const CloudflareAddr = "127.0.0.1:10443"

// CloudflareServer is the website's name behind Cloudflare's proxy (orange
// cloud, see infra/main.tf), for networks that can't reach the server's own
// address. Empty when the server has no domain.
func CloudflareServer(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return "web." + host
}

// CloudflareFront sends WebSocket upgrades on path to Xray at addr and
// everything else to site, so the tunnel and the website share the name.
func CloudflareFront(site http.Handler, path, addr string) http.Handler {
	xray := &httputil.ReverseProxy{
		Rewrite:  func(r *httputil.ProxyRequest) { r.SetURL(&url.URL{Scheme: "http", Host: addr}) },
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
			httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade") {
			xray.ServeHTTP(w, r)
			return
		}
		site.ServeHTTP(w, r)
	})
}

// cloudflareIPs are Cloudflare's addresses for name, looked up here so the
// apps needn't resolve it before their tunnel is up. Any of Cloudflare's
// addresses serves the name, so an old answer keeps working.
func (r *Runtime) cloudflareIPs(name string) []string {
	r.cfMu.Lock()
	defer r.cfMu.Unlock()
	if len(r.cfIPs) > 0 && time.Since(r.cfAt) < time.Hour {
		return r.cfIPs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupHost(ctx, name); err == nil && len(ips) > 0 {
		r.cfIPs, r.cfAt = ips, time.Now()
	}
	return r.cfIPs
}
