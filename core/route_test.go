package nomaxcore

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestPlanLegs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	savedPort, savedTrace := probePort, traceURL
	defer func() { probePort, traceURL = savedPort, savedTrace }()
	_, probePort, _ = net.SplitHostPort(ln.Addr().String())
	loc := "GB"
	trace := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ip=192.0.2.9\nloc=%s\ntls=TLSv1.3\n", loc)
	}))
	defer trace.Close()
	traceURL = trace.URL

	// 192.0.2.0/24 is for documentation: nothing answers there.
	up, down := "127.0.0.1", "192.0.2.1"
	p := profile.Profile{
		Host:       up,
		WireGuard:  profile.WireGuardConf{Port: 51820, ServerPublicKey: "key"},
		Cloudflare: &profile.CloudflareConf{Host: "web.vpn.test"},
		Relays:     []profile.Relay{{Address: down, Country: "DE"}, {Address: up, Country: "DE"}},
	}
	type want struct {
		endpoint       string
		relay, blocked bool
	}
	check := func(name string, p profile.Profile, route, serverIP string, wants ...want) {
		t.Helper()
		legs := planLegs(context.Background(), p, route, "", serverIP)
		if len(legs) != len(wants) {
			t.Fatalf("%s: %d legs %+v, want %d", name, len(legs), legs, len(wants))
		}
		for i, w := range wants {
			l := legs[i]
			if l.endpoint != w.endpoint || l.relay != w.relay || l.blocked != w.blocked {
				t.Errorf("%s: leg %d is %+v, want %+v", name, i, l, w)
			}
			if l.relay && slices.Contains(l.order, profile.Cloudflare) {
				t.Errorf("%s: the relay leg tries Cloudflare's route", name)
			}
			if l.blocked && !l.relay && l.order[0] != profile.Cloudflare {
				t.Errorf("%s: a blocked server doesn't try Cloudflare first", name)
			}
		}
	}

	check("auto elsewhere", p, RouteAuto, up, want{endpoint: up}, want{endpoint: up, relay: true})
	loc = "DE"
	check("auto in the relays' country", p, RouteAuto, up, want{endpoint: up, relay: true}, want{endpoint: up})
	check("exit in the relays' country", p, RouteExit, up, want{endpoint: up, relay: true}, want{endpoint: up})
	loc = "GB"
	blocked := p
	blocked.Host = down
	check("auto, server blocked", blocked, RouteAuto, down, want{endpoint: up, relay: true}, want{endpoint: down, blocked: true})
	check("direct", p, RouteDirect, up, want{endpoint: up})
	check("relay", p, RouteRelay, up, want{endpoint: up, relay: true})
	silent := p
	silent.Relays = []profile.Relay{{Address: down, Country: "DE"}}
	check("relay that doesn't answer", silent, RouteRelay, up, want{endpoint: down, relay: true, blocked: true})
	check("auto, relay doesn't answer", silent, RouteAuto, up, want{endpoint: up})
	none := p
	none.Relays = nil
	check("auto without relays", none, RouteAuto, up, want{endpoint: up})
	if legs := planLegs(context.Background(), none, RouteRelay, "", up); legs != nil {
		t.Errorf("relay route without relays: %+v", legs)
	}
}

func TestEndpoint(t *testing.T) {
	cases := []struct {
		profile, want string
	}{
		{`{"host":"127.0.0.1"}`, "127.0.0.1"},
		{`{"host":"nowhere.invalid","ips":["2001:db8::1","192.0.2.1"]}`, "192.0.2.1"},
		{`{"host":"nowhere.invalid","relays":[{"address":"192.0.2.7","country":"DE"}]}`, "192.0.2.7"},
		{`{"host":"nowhere.invalid"}`, ""},
	}
	for _, c := range cases {
		if got := Endpoint(c.profile); got != c.want {
			t.Errorf("Endpoint(%s) = %q, want %q", c.profile, got, c.want)
		}
	}
}
