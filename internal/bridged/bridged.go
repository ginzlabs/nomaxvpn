// Package bridged builds the clients for the protocols Xray can't speak,
// which the apps and ops probe reach through a local SOCKS5 bridge.
package bridged

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ginzlabs/nomaxvpn/internal/anytls"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"github.com/ginzlabs/nomaxvpn/internal/mieru"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/trusttunnel"
)

// Client dials the server at endpointIP directly.
func Client(p profile.Profile, protocol, endpointIP string) (bridge.Dialer, error) {
	if !profile.Offered(p, protocol) {
		return nil, fmt.Errorf("server offers no %s", protocol)
	}
	addr := func(port int) string { return net.JoinHostPort(endpointIP, strconv.Itoa(port)) }
	switch protocol {
	case profile.TrustTunnel:
		t := p.TrustTunnel
		return trusttunnel.NewClient(trusttunnel.Config{Address: addr(t.Port), Host: p.Host, Username: t.Username, Password: t.Password}), nil
	case profile.AnyTLS:
		return anytls.NewClient(anytls.Config{Address: addr(p.AnyTLS.Port), Host: p.Host, Password: p.AnyTLS.Password})
	case profile.Mieru:
		m := p.Mieru
		return mieru.NewClient(mieru.Config{Address: addr(m.Port), Username: m.Username, Password: m.Password})
	}
	return nil, fmt.Errorf("%s is not a bridged protocol", protocol)
}
