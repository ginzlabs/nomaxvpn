package nomaxcore

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/ginzlabs/nomaxvpn/internal/directory"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// moved asks the directory where the server is now, once every way the
// profile knows has failed. It returns the profile with the directory's
// addresses and relays, and the server's address to use. A new name needs
// a new profile, which the app fetches through the directory itself.
func moved(ctx context.Context, r int64, p profile.Profile, serverIP string) (profile.Profile, string, bool) {
	var relays []string
	for _, rl := range p.Relays {
		relays = append(relays, rl.Address)
	}
	e, err := directory.Lookup(ctx)
	if err != nil || !e.Differs(p.Host, append(slices.Clone(p.IPs), serverIP), relays) {
		return p, serverIP, false
	}
	if e.Host != p.Host {
		emit(r, "", stateInfo, "The server has moved to %s. Open NoMax to update.", e.Host)
		return p, serverIP, false
	}
	q := p
	q.IPs = e.IPs
	if len(e.Relays) > 0 {
		q.Relays = nil
		for _, a := range e.Relays {
			q.Relays = append(q.Relays, profile.Relay{Address: a, Country: profile.RelayCountry})
		}
	}
	ip := serverIP
	for _, a := range e.IPs {
		if net.ParseIP(a).To4() != nil {
			ip = a
			break
		}
	}
	emit(r, "", stateInfo, "Found the server's new addresses. Trying them…")
	return q, ip, true
}

// Routes say how the tunnel reaches the server.
const (
	// RouteAuto goes through a relay on networks in its country, or when the
	// server's address doesn't answer, and straight to the server otherwise;
	// whichever it starts with, it tries the other if nothing gets through.
	RouteAuto = "auto"
	// RouteDirect goes to the server's own address (and Cloudflare's route).
	RouteDirect = "direct"
	// RouteRelay goes through a relay, which forwards every port to the server.
	RouteRelay = "relay"
	// RouteExit picks the way in like Auto and uses the device's exit login,
	// whose traffic leaves the server through the first relay.
	RouteExit = "exit"
)

// leg is one way to the server: where the protocols connect, and the order
// to try them in.
type leg struct {
	endpoint string
	relay    bool
	blocked  bool // the server's address didn't answer
	order    []string
}

// traceURL says which country the network's address is in (its loc= line).
var traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// country is the network's country code, "" if the lookup failed.
func country(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return ""
	}
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if loc, ok := strings.CutPrefix(sc.Text(), "loc="); ok {
			return strings.ToUpper(strings.TrimSpace(loc))
		}
	}
	return ""
}

// reachRelay returns the first relay that answers on the probe port, which
// it forwards to the server, so an answer means the server is reachable
// through it. "" means none did.
func reachRelay(ctx context.Context, relays []profile.Relay) string {
	if len(relays) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	answered := make(chan int, len(relays))
	for i, r := range relays {
		go func() {
			d := net.Dialer{Timeout: probeWait}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.Address, probePort))
			if err != nil {
				answered <- -1
				return
			}
			c.Close()
			answered <- i
		}()
	}
	for range relays {
		if i := <-answered; i >= 0 {
			return relays[i].Address
		}
	}
	return ""
}

// withoutAround drops the protocols that don't connect to the server's
// address (Cloudflare's route), which a relay can't carry.
func withoutAround(order []string) []string {
	return slices.DeleteFunc(slices.Clone(order), func(p string) bool { return slices.Contains(around, p) })
}

// planLegs works out the ways to try, in turn, for route. serverIP is the
// server's address the app resolved. No legs means route is the relay and
// the profile has none.
func planLegs(ctx context.Context, p profile.Profile, route, preferred, serverIP string) []leg {
	order := autoOrder(p, preferred)
	direct := func() leg {
		reached := reach(ctx, p.Host, serverIP, p.IPs)
		if reached == "" {
			return leg{endpoint: serverIP, blocked: true, order: aroundFirst(order)}
		}
		return leg{endpoint: reached, order: order}
	}
	viaRelay := func() (leg, bool) {
		ip := reachRelay(ctx, p.Relays)
		return leg{endpoint: ip, relay: true, order: withoutAround(order)}, ip != ""
	}
	switch route {
	case RouteDirect:
		return []leg{direct()}
	case RouteRelay:
		if len(p.Relays) == 0 {
			return nil
		}
		l, ok := viaRelay()
		if !ok {
			// None answers on TCP; UDP may still get through.
			l.endpoint, l.blocked = p.Relays[0].Address, true
		}
		return []leg{l}
	}
	if len(p.Relays) == 0 {
		return []leg{direct()}
	}
	var (
		wg      sync.WaitGroup
		loc     string
		d, rl   leg
		relayOK bool
	)
	wg.Go(func() { loc = country(ctx) })
	wg.Go(func() { d = direct() })
	wg.Go(func() { rl, relayOK = viaRelay() })
	wg.Wait()
	switch {
	case !relayOK:
		return []leg{d}
	case loc != "" && loc == p.Relays[0].Country || d.blocked:
		return []leg{rl, d}
	}
	return []leg{d, rl}
}
