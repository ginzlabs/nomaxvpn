package nomaxcore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Some filters let a WireGuard handshake through and then drop what
// follows, so a handshake alone proves little. pingTun sits between WireGuard
// (or AmneziaWG) and the OS tunnel and lets check send pings through the
// engine with no network stack: the requests join what the engine reads from
// the OS, and their replies are taken out of what it writes back.
type pingTun struct {
	tun.Device
	src, dst netip.Addr // IPv4; dst invalid means there's nothing to ping
	id       uint16
	size     int // ICMP payload bytes

	// The engine's reads come from pump, so an injected ping needn't wait for
	// the OS to send something.
	inject chan []byte
	reads  chan pumped
	taken  chan struct{}
	bufs   [][]byte
	sizes  []int

	done      chan struct{}
	closeOnce sync.Once

	pinging sync.Mutex // one ping run at a time
	seq     uint16
	replies chan uint16
}

type pumped struct {
	n   int
	err error
}

const (
	pumpOffset = 16 // room for the Darwin utun header in front of each packet
	pingGap    = 4 * time.Millisecond
	// pingWait is how long the pings' replies may take, on top of the handshake.
	pingWait = 2 * time.Second
	// checkPings carry about 75 KB each way, past the few KB the filters let
	// through; alivePings are the watchdog's lighter look.
	checkPings = 64
	alivePings = 16
)

// newPingTun wraps an engine's OS tunnel. addrs are the tunnel's own addresses;
// pings go from its IPv4 to dst.
func newPingTun(dev tun.Device, addrs []string, dst netip.Addr, mtu int) *pingTun {
	t := &pingTun{
		Device:  dev,
		id:      uint16(rand.Uint32()),
		size:    min(1200, mtu-28),
		inject:  make(chan []byte, checkPings),
		reads:   make(chan pumped),
		taken:   make(chan struct{}),
		done:    make(chan struct{}),
		replies: make(chan uint16, checkPings),
	}
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Addr().Is4() {
			t.src = pfx.Addr()
			break
		}
	}
	if t.src.IsValid() && dst.Is4() && t.size > 0 {
		t.dst = dst
	}
	n := dev.BatchSize()
	t.bufs, t.sizes = make([][]byte, n), make([]int, n)
	for i := range t.bufs {
		t.bufs[i] = make([]byte, pumpOffset+65535)
	}
	go t.pump()
	return t
}

// pingTarget is the server's own IPv4, which answers pings from inside the
// tunnel, or the tunnel's DNS server when the profile lists no address.
func pingTarget(p profile.Profile) netip.Addr {
	for _, list := range [][]string{p.IPs, p.WireGuard.DNS} {
		for _, s := range list {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				return a
			}
		}
	}
	return netip.Addr{}
}

func (t *pingTun) pump() {
	for {
		n, err := t.Device.Read(t.bufs, t.sizes, pumpOffset)
		select {
		case t.reads <- pumped{n, err}:
		case <-t.done:
			return
		}
		select {
		case <-t.taken:
		case <-t.done:
			return
		}
	}
}

func (t *pingTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.inject:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case r := <-t.reads:
		n := min(r.n, len(bufs))
		for i := range n {
			sizes[i] = copy(bufs[i][offset:], t.bufs[i][pumpOffset:pumpOffset+t.sizes[i]])
		}
		t.taken <- struct{}{}
		return n, r.err
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *pingTun) Write(bufs [][]byte, offset int) (int, error) {
	var keep [][]byte
	for i, b := range bufs {
		if seq, ok := t.reply(b[offset:]); ok {
			select {
			case t.replies <- seq:
			default:
			}
			if keep == nil {
				keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
			}
			continue
		}
		if keep != nil {
			keep = append(keep, b)
		}
	}
	if keep == nil {
		return t.Device.Write(bufs, offset)
	}
	if len(keep) > 0 {
		if _, err := t.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

func (t *pingTun) Close() error {
	t.closeOnce.Do(func() { close(t.done) })
	return t.Device.Close()
}

// reply returns the sequence number of an echo reply to one of our pings.
func (t *pingTun) reply(pkt []byte) (uint16, bool) {
	if !t.dst.IsValid() || len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[ihl] != 0 || binary.BigEndian.Uint16(pkt[ihl+4:]) != t.id ||
		netip.AddrFrom4([4]byte(pkt[12:16])) != t.dst {
		return 0, false
	}
	return binary.BigEndian.Uint16(pkt[ihl+6:]), true
}

// errNoPing is ping's error when the tunnel has no IPv4 or the profile no
// address to ping.
var errNoPing = errors.New("nothing to ping")

// ping sends count pings through the engine, spaced so a burst doesn't
// overflow a queue on the way, and returns how many came back before ctx
// ended.
func (t *pingTun) ping(ctx context.Context, count int) (int, error) {
	if !t.dst.IsValid() {
		return 0, errNoPing
	}
	t.pinging.Lock()
	defer t.pinging.Unlock()
	for len(t.replies) > 0 {
		<-t.replies
	}
	first := t.seq
	t.seq += uint16(count)
	got := make(map[uint16]bool, count)
	collect := func() {
		for {
			select {
			case s := <-t.replies:
				if s-first < uint16(count) {
					got[s] = true
				}
			default:
				return
			}
		}
	}
	for i := range count {
		select {
		case t.inject <- echoRequest(t.src, t.dst, t.id, first+uint16(i), t.size):
		case <-ctx.Done():
			return len(got), nil
		case <-t.done:
			return len(got), os.ErrClosed
		}
		collect()
		if !sleep(ctx, pingGap) {
			return len(got), nil
		}
	}
	for len(got) < count {
		select {
		case s := <-t.replies:
			if s-first < uint16(count) {
				got[s] = true
			}
		case <-ctx.Done():
			return len(got), nil
		case <-t.done:
			return len(got), os.ErrClosed
		}
	}
	return len(got), nil
}

// pingCheck pings through the engine and fails unless most pings come back.
func (t *pingTun) pingCheck(ctx context.Context, count int) (string, error) {
	start := time.Now()
	got, err := t.ping(ctx, count)
	if err != nil {
		return "", err
	}
	if got*2 < count {
		return "", pingLoss{got, count}
	}
	return fmt.Sprintf("%d KB of pings answered in %d ms", count*(t.size+28)>>10, time.Since(start).Milliseconds()), nil
}

// pingLoss is a check that most pings didn't survive.
type pingLoss struct{ got, sent int }

func (e pingLoss) Error() string {
	if e.got == 0 {
		return "no reply through the tunnel"
	}
	return fmt.Sprintf("only %d of %d pings came back", e.got, e.sent)
}

// echoRequest is an IPv4 ICMP echo request with size bytes of payload.
func echoRequest(src, dst netip.Addr, id, seq uint16, size int) []byte {
	pkt := make([]byte, 28+size)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], seq)
	pkt[8], pkt[9] = 64, 1
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], checksum(pkt[:20]))
	icmp := pkt[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	for i := 8; i < len(icmp); i++ {
		icmp[i] = byte(i)
	}
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
	return pkt
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
