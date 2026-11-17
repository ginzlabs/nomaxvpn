// Package trusttunnel speaks TrustTunnel (github.com/TrustTunnel/TrustTunnel,
// PROTOCOL.md): HTTP/2 CONNECT to a website with a password, one stream per
// TCP connection and one "_udp2" stream carrying every datagram.
package trusttunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

const (
	udpHost   = "_udp2"
	checkHost = "_check"
	icmpHost  = "_icmp"
	// maxFrame bounds a datagram frame: 65535 of payload plus the addresses.
	maxFrame = 65535 + 64
)

// datagram is one frame of the _udp2 stream. Frames to the server carry an
// app name (always empty here); frames from it don't.
type datagram struct {
	src, dst netip.AddrPort
	payload  []byte
}

func appendFrame(b []byte, d datagram, toServer bool) []byte {
	n := 16 + 2 + 16 + 2 + len(d.payload)
	if toServer {
		n++
	}
	b = binary.BigEndian.AppendUint32(b, uint32(n))
	b = appendAddrPort(b, d.src)
	b = appendAddrPort(b, d.dst)
	if toServer {
		b = append(b, 0)
	}
	return append(b, d.payload...)
}

// readFrame reads one frame into buf, which must hold maxFrame bytes.
func readFrame(r io.Reader, buf []byte, fromClient bool) (datagram, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return datagram{}, err
	}
	n := int(binary.BigEndian.Uint32(l[:]))
	if n < 36 || n > maxFrame {
		return datagram{}, errors.New("trusttunnel: bad frame length")
	}
	b := buf[:n]
	if _, err := io.ReadFull(r, b); err != nil {
		return datagram{}, err
	}
	d := datagram{src: addrPort(b[0:18]), dst: addrPort(b[18:36])}
	b = b[36:]
	if fromClient {
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return datagram{}, errors.New("trusttunnel: bad app name")
		}
		b = b[1+int(b[0]):]
	}
	d.payload = b
	return d, nil
}

// Addresses are 16 bytes, IPv4 with 12 zero bytes in front.
func appendAddrPort(b []byte, a netip.AddrPort) []byte {
	var ip [16]byte
	if v := a.Addr().Unmap(); v.Is4() {
		v4 := v.As4()
		copy(ip[12:], v4[:])
	} else {
		ip = v.As16()
	}
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}

func addrPort(b []byte) netip.AddrPort {
	ip := netip.AddrFrom16([16]byte(b[:16]))
	if v4 := [12]byte(b[:12]); v4 == [12]byte{} && ip != netip.IPv6Loopback() {
		ip = netip.AddrFrom4([4]byte(b[12:16]))
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:18]))
}
