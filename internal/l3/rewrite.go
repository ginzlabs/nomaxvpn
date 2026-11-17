package l3

import (
	"bytes"
	"encoding/binary"
	"net"
)

// rewrite replaces the source (src) or destination address of an IP packet
// that equals from4/from6 with to4/to6, and fixes the IP, TCP, UDP and ICMPv6
// checksums. Other addresses pass unchanged. It reports false for a packet to
// drop: not IP, truncated, or a family with no address to translate to.
func rewrite(pkt []byte, src bool, from4, to4, from6, to6 net.IP) bool {
	if len(pkt) == 0 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl || to4 == nil {
			return false
		}
		off := 16
		if src {
			off = 12
		}
		addr := pkt[off : off+4]
		if !bytes.Equal(addr, from4.To4()) {
			return true
		}
		old := [4]byte(addr)
		copy(addr, to4.To4())
		adjust(pkt, 10, old[:], addr)
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return true // later fragments carry no TCP/UDP header
		}
		fixL4(pkt[9], pkt[ihl:], old[:], addr, false)
		return true
	case 6:
		if len(pkt) < 40 || to6 == nil {
			return false
		}
		off := 24
		if src {
			off = 8
		}
		addr := pkt[off : off+16]
		if from6 == nil || !bytes.Equal(addr, from6.To16()) {
			return true
		}
		old := [16]byte(addr)
		copy(addr, to6.To16())
		fixL4(pkt[6], pkt[40:], old[:], addr, true)
		return true
	}
	return false
}

// fixL4 updates the transport checksum, which covers the addresses through the
// pseudo-header. Packets behind IPv6 extension headers are left alone.
func fixL4(proto byte, l4, old, new []byte, v6 bool) {
	switch {
	case proto == 6 && len(l4) >= 18:
		adjust(l4, 16, old, new)
	case proto == 17 && len(l4) >= 8:
		if !v6 && binary.BigEndian.Uint16(l4[6:8]) == 0 {
			return // IPv4 UDP without a checksum
		}
		adjust(l4, 6, old, new)
		if binary.BigEndian.Uint16(l4[6:8]) == 0 {
			binary.BigEndian.PutUint16(l4[6:8], 0xffff)
		}
	case proto == 58 && v6 && len(l4) >= 4:
		adjust(l4, 2, old, new)
	}
}

// adjust updates the ones'-complement checksum at b[off:] for old replaced by
// new (RFC 1624): HC' = ~(~HC + ~m + m').
func adjust(b []byte, off int, old, new []byte) {
	sum := uint32(^binary.BigEndian.Uint16(b[off:]))
	for i := 0; i+1 < len(old); i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(old[i:])) + uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(b[off:], ^uint16(sum))
}
