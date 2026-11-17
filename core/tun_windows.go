package nomaxcore

// Nothing hands Windows apps a tunnel: Xray creates the Wintun interface
// (wintun.dll next to the exe), routes everything into it, sets its DNS and
// keeps its own sockets out of it. Every protocol runs behind that interface.
// WireGuard, AmneziaWG, OpenVPN and OpenConnect, which want packets, get a
// userspace network stack that the local bridge dials through.

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TunName is the Windows network adapter's name.
const TunName = "NoMax"

// No 50 MB ceiling here, as there is in a Network Extension.
const memoryLimit = 0

// tunSetup is the time Xray takes to create the adapter, route it and set its DNS.
const tunSetup = 3 * time.Second

// stack is the userspace network of the WireGuard or L3 engine starting now.
var stack *stackDialer

func findTunFd() int { return 0 }

// packetTun is a userspace stack with addrs, for feedSystemTun to put behind the adapter.
func packetTun(_ int, p profile.Profile, addrs []string) (tun.Device, error) {
	var local, perFamily []netip.Addr
	for _, a := range addrs {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, err
		}
		local = append(local, pfx.Addr())
		if !slices.ContainsFunc(perFamily, func(b netip.Addr) bool { return b.Is4() == pfx.Addr().Is4() }) {
			perFamily = append(perFamily, pfx.Addr())
		}
	}
	var dns []netip.Addr
	for _, d := range p.WireGuard.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, a)
		}
	}
	dev, n, err := netstack.CreateNetTUN(local, dns, tunMTU(p))
	if err != nil {
		return nil, err
	}
	stack = &stackDialer{n, perFamily}
	return dev, nil
}

// SystemTun is the adapter Xray creates for the profile: everything routed
// into it, IPv6 too when the tunnel has an address for it, and DNS kept inside.
func SystemTun(p profile.Profile) *profile.SystemTun {
	routes := []string{"0.0.0.0/0"}
	for _, a := range p.WireGuard.Address {
		if strings.Contains(a, ":") {
			routes = append(routes, "::/0")
			break
		}
	}
	return &profile.SystemTun{
		Name:    TunName,
		Gateway: p.WireGuard.Address,
		DNS:     p.WireGuard.DNS,
		Routes:  routes,
		// misconfigtun blocks IPv6 when it has no route into the adapter, so it can't leak.
		BlockLeaks: []string{"dns", "misconfigtun"},
	}
}

func xrayInbound(p profile.Profile, _ int, endpointIP string) profile.ClientInbound {
	return profile.ClientInbound{TunMTU: tunMTU(p), Address: endpointIP, Tun: SystemTun(p)}
}

// feedSystemTun puts the adapter in front of a WireGuard or L3 engine's stack.
func feedSystemTun(p profile.Profile, protocol string, fd int) error {
	switch kindOf(protocol) {
	case kindWireGuard, kindL3:
	default:
		return nil
	}
	d := stack
	stack = nil
	if d == nil {
		return errors.New("the network stack is missing")
	}
	return startBridged(p, protocol, fd, *d)
}

// pinned is the route that sends the server's address over the physical
// network, so the engines' own sockets (all but Xray's, which it binds itself)
// skip the adapter.
var pinned struct {
	luid winipcfg.LUID
	dst  netip.Prefix
	via  netip.Addr
}

func pinServer(endpointIP string) error {
	ip, err := netip.ParseAddr(endpointIP)
	if err != nil {
		return fmt.Errorf("server address %q: %w", endpointIP, err)
	}
	dst := netip.PrefixFrom(ip, ip.BitLen())
	if pinned.dst == dst {
		return nil
	}
	unpinServer()
	luid, via, err := defaultRoute(ip.Is6())
	if err != nil {
		return err
	}
	if err := luid.AddRoute(dst, via, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	pinned.luid, pinned.dst, pinned.via = luid, dst, via
	return nil
}

func unpinServer() {
	if !pinned.dst.IsValid() {
		return
	}
	pinned.luid.DeleteRoute(pinned.dst, pinned.via)
	pinned.dst = netip.Prefix{}
}

// clearTun takes the routes and DNS off a NoMax adapter that still has them
// once every engine is down: a teardown gone wrong would otherwise leave the
// PC sending everything into an adapter nothing reads. It says whether there
// was anything to take off.
func clearTun() bool {
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return false
	}
	cleared := false
	for _, a := range ifs {
		if a.FriendlyName() != TunName || !captures(a.LUID) {
			continue
		}
		for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			a.LUID.FlushRoutes(f)
			a.LUID.FlushDNS(f)
			a.LUID.FlushIPAddresses(f)
		}
		cleared = true
	}
	return cleared
}

// captures says whether the adapter has DNS servers or a default route.
func captures(luid winipcfg.LUID) bool {
	if dns, err := luid.DNS(); err == nil && len(dns) > 0 {
		return true
	}
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(f)
		if err != nil {
			continue
		}
		for i := range rows {
			if rows[i].InterfaceLUID == luid && rows[i].DestinationPrefix.Prefix().Bits() == 0 {
				return true
			}
		}
	}
	return false
}

// defaultRoute is the physical network's default route with the lowest metric.
func defaultRoute(v6 bool) (winipcfg.LUID, netip.Addr, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if v6 {
		family = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, netip.Addr{}, err
	}
	best, bestMetric := -1, uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		ifc, err := r.InterfaceLUID.Interface()
		if err != nil || ifc.Alias() == TunName || ifc.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !ipif.Connected {
			continue
		}
		if m := r.Metric + ipif.Metric; best < 0 || m < bestMetric {
			best, bestMetric = i, m
		}
	}
	if best < 0 {
		return 0, netip.Addr{}, errors.New("no network connection")
	}
	return rows[best].InterfaceLUID, rows[best].NextHop.Addr(), nil
}
