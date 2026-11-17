//go:build !windows

package nomaxcore

import (
	"os"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"golang.org/x/sys/unix"
)

// Network Extensions are killed above 50 MB.
const memoryLimit = 40 << 20

// tunSetup is the time the interface takes to come up per protocol: none, as
// the OS hands it over ready.
const tunSetup = 0

// packetTun is the OS tunnel for WireGuard and the L3 engines, on a duplicate
// of fd that the engine owns.
func packetTun(fd int, _ profile.Profile, _ []string) (tun.Device, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	t, err := openTun(dup)
	if err != nil {
		unix.Close(dup)
		return nil, err
	}
	return t, nil
}

// xrayInbound is Xray's tun inbound on the OS tunnel's fd.
func xrayInbound(p profile.Profile, fd int, endpointIP string) profile.ClientInbound {
	os.Setenv("xray.tun.fd", strconv.Itoa(fd))
	return profile.ClientInbound{TunMTU: tunMTU(p), Address: endpointIP}
}

// feedSystemTun has nothing to do: the engines run on the OS tunnel itself.
func feedSystemTun(profile.Profile, string, int) error { return nil }

// pinServer has nothing to do: the OS keeps the engine's own sockets out of the tunnel.
func pinServer(string) error { return nil }

func unpinServer() {}

// clearTun has nothing to clear: the system owns the tunnel interface.
func clearTun() bool { return false }
