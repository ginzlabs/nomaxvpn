package nomaxcore

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/unix"
)

// openTun takes ownership of fd, a duplicate of the packet tunnel's utun socket.
func openTun(fd int) (tun.Device, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/tun"), 0)
}

// findTunFd locates the packet tunnel's utun socket among the extension's open
// file descriptors, as WireGuardKit does.
func findTunFd() int {
	info := unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	for fd := 0; fd <= 1024; fd++ {
		sa, err := unix.Getpeername(fd)
		if err != nil {
			continue
		}
		ctl, ok := sa.(*unix.SockaddrCtl)
		if !ok {
			continue
		}
		if info.Id == 0 {
			if err := unix.IoctlCtlInfo(fd, &info); err != nil {
				continue
			}
		}
		if ctl.ID == info.Id {
			return fd
		}
	}
	return -1
}
