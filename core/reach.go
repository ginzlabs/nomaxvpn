package nomaxcore

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Auto first checks that the server's address answers at all, with a TCP
// connection to its HTTPS port. A network that blocks the address drops every
// protocol aimed at it, each after its whole budget.
var probePort = "443"

const probeWait = 2 * time.Second

// reach returns the first of the server's addresses that answers: endpointIP,
// else another of known (the profile's) or of those host resolves to (IPv6
// when only IPv4 is blocked). "" means none did, so only a route around the
// address can work.
func reach(ctx context.Context, host, endpointIP string, known []string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*probeWait)
	defer cancel()
	ips := []string{endpointIP}
	lookup, done := context.WithTimeout(ctx, probeWait)
	addrs, _ := net.DefaultResolver.LookupHost(lookup, host)
	done()
	for _, a := range append(slices.Clone(known), addrs...) {
		if !slices.Contains(ips, a) {
			ips = append(ips, a)
		}
	}
	answered := make(chan int, len(ips))
	for i, ip := range ips {
		go func() {
			d := net.Dialer{Timeout: probeWait}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, probePort))
			switch {
			case err == nil:
				c.Close()
			case !strings.Contains(err.Error(), "refused"):
				// A refusal answers too; a blocked address stays silent.
				answered <- -1
				return
			}
			answered <- i
		}()
	}
	ok := make([]bool, len(ips))
	for range ips {
		if i := <-answered; i >= 0 {
			if i == 0 {
				return endpointIP
			}
			ok[i] = true
		}
	}
	if i := slices.Index(ok, true); i >= 0 {
		return ips[i]
	}
	return ""
}

// around are the protocols that don't connect to the server's address.
var around = []string{profile.Cloudflare}

// aroundFirst moves the protocols that go around the server's address to the
// front of order, for a network that blocks it. The others stay, in case it
// only blocks TCP.
func aroundFirst(order []string) []string {
	out := make([]string, 0, len(order))
	for _, p := range order {
		if slices.Contains(around, p) {
			out = append(out, p)
		}
	}
	for _, p := range order {
		if !slices.Contains(around, p) {
			out = append(out, p)
		}
	}
	return out
}
