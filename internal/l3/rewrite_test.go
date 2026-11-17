package l3

import (
	"encoding/binary"
	"net"
	"testing"
)

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, p := range parts {
		for i := 0; i < len(p); i += 2 {
			w := uint32(p[i]) << 8
			if i+1 < len(p) {
				w |= uint32(p[i+1])
			}
			sum += w
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func ipv4(proto byte, src, dst net.IP, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	copy(h[12:], src.To4())
	copy(h[16:], dst.To4())
	binary.BigEndian.PutUint16(h[10:], checksum(h))
	pkt := append(h, l4...)
	setL4Sum(pkt[20:], proto, pseudo4(pkt))
	return pkt
}

func ipv6(proto byte, src, dst net.IP, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0], h[6], h[7] = 0x60, proto, 64
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	copy(h[8:], src.To16())
	copy(h[24:], dst.To16())
	pkt := append(h, l4...)
	setL4Sum(pkt[40:], proto, pseudo6(pkt))
	return pkt
}

func pseudo4(pkt []byte) []byte {
	p := append(append([]byte{}, pkt[12:20]...), 0, pkt[9], 0, 0)
	binary.BigEndian.PutUint16(p[10:], uint16(len(pkt)-20))
	return p
}

func pseudo6(pkt []byte) []byte {
	p := append(append([]byte{}, pkt[8:40]...), 0, 0, 0, 0, 0, 0, 0, pkt[6])
	binary.BigEndian.PutUint32(p[32:], uint32(len(pkt)-40))
	return p
}

func sumOffset(proto byte) int {
	switch proto {
	case 6:
		return 16
	case 17:
		return 6
	}
	return 2
}

func setL4Sum(l4 []byte, proto byte, pseudo []byte) {
	off := sumOffset(proto)
	binary.BigEndian.PutUint16(l4[off:], 0)
	s := checksum(pseudo, l4)
	if s == 0 && proto == 17 {
		s = 0xffff
	}
	binary.BigEndian.PutUint16(l4[off:], s)
}

func TestRewrite(t *testing.T) {
	local4, remote4 := net.ParseIP("10.8.0.7").To4(), net.ParseIP("10.8.2.7").To4()
	local6, remote6 := net.ParseIP("fd08::7"), net.ParseIP("fd08:2::7")
	peer4, peer6 := net.ParseIP("1.1.1.1"), net.ParseIP("2606:4700:4700::1111")
	tcp := make([]byte, 20+11) // header, then an odd-length payload
	tcp[12] = 5 << 4
	copy(tcp[20:], "hello world")
	udp := make([]byte, 8+5)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], "hello")
	icmp6 := []byte{128, 0, 0, 0, 0, 1, 0, 1}

	cases := []struct {
		name string
		v6   bool
		pkt  func() []byte
		want func() []byte
	}{
		{"tcp4 out", false, func() []byte { return ipv4(6, local4, peer4, append([]byte{}, tcp...)) },
			func() []byte { return ipv4(6, remote4, peer4, append([]byte{}, tcp...)) }},
		{"udp4 out", false, func() []byte { return ipv4(17, local4, peer4, append([]byte{}, udp...)) },
			func() []byte { return ipv4(17, remote4, peer4, append([]byte{}, udp...)) }},
		{"tcp6 out", true, func() []byte { return ipv6(6, local6, peer6, append([]byte{}, tcp...)) },
			func() []byte { return ipv6(6, remote6, peer6, append([]byte{}, tcp...)) }},
		{"icmp6 out", true, func() []byte { return ipv6(58, local6, peer6, append([]byte{}, icmp6...)) },
			func() []byte { return ipv6(58, remote6, peer6, append([]byte{}, icmp6...)) }},
	}
	for _, c := range cases {
		pkt := c.pkt()
		if !rewrite(pkt, true, local4, remote4, local6, remote6) {
			t.Fatalf("%s: dropped", c.name)
		}
		if want := c.want(); string(pkt) != string(want) {
			t.Errorf("%s:\n got %x\nwant %x", c.name, pkt, want)
		}
	}

	// Inbound: destination goes from the assigned address back to the interface's.
	in := ipv4(6, peer4, remote4, append([]byte{}, tcp...))
	if !rewrite(in, false, remote4, local4, remote6, local6) {
		t.Fatal("inbound dropped")
	}
	if want := ipv4(6, peer4, local4, append([]byte{}, tcp...)); string(in) != string(want) {
		t.Errorf("inbound:\n got %x\nwant %x", in, want)
	}

	if rewrite(ipv6(6, local6, peer6, append([]byte{}, tcp...)), true, local4, remote4, local6, nil) {
		t.Error("IPv6 without an assigned address should be dropped")
	}
	if rewrite([]byte{0x45, 0}, true, local4, remote4, local6, remote6) {
		t.Error("truncated packet should be dropped")
	}
}
