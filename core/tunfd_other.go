//go:build !darwin && !android && !windows

package nomaxcore

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func findTunFd() int { return -1 }

func openTun(fd int) (tun.Device, error) {
	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/tun"), 0)
}
