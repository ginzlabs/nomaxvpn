package nomaxcore

import "github.com/amnezia-vpn/amneziawg-go/tun"

// The app passes the VpnService descriptor in, so there is nothing to find.
func findTunFd() int { return -1 }

// openTun takes ownership of fd. Apps may not watch routing sockets, so the
// device is unmonitored, as in the WireGuard Android app.
func openTun(fd int) (tun.Device, error) {
	t, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return t, err
}
