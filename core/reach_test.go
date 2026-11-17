package nomaxcore

import (
	"context"
	"net"
	"slices"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestReach(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	saved := probePort
	defer func() { probePort = saved }()
	_, probePort, _ = net.SplitHostPort(ln.Addr().String())

	ctx := context.Background()
	if got := reach(ctx, "127.0.0.1", "127.0.0.1", nil); got != "127.0.0.1" {
		t.Errorf("answering address: got %q", got)
	}
	// 192.0.2.0/24 is for documentation: nothing answers there.
	if got := reach(ctx, "127.0.0.1", "192.0.2.1", nil); got != "127.0.0.1" {
		t.Errorf("blocked endpoint, host answers elsewhere: got %q", got)
	}
	if got := reach(ctx, "192.0.2.2", "192.0.2.1", []string{"127.0.0.1"}); got != "127.0.0.1" {
		t.Errorf("blocked endpoint, the profile's other address answers: got %q", got)
	}
	if got := reach(ctx, "192.0.2.2", "192.0.2.1", nil); got != "" {
		t.Errorf("nothing answers: got %q", got)
	}
	ln.Close()
	if got := reach(ctx, "127.0.0.1", "127.0.0.1", nil); got != "127.0.0.1" {
		t.Errorf("a refusal is an answer: got %q", got)
	}
}

func TestAroundFirst(t *testing.T) {
	in := []string{profile.WireGuard, profile.Hysteria2, profile.Cloudflare, profile.Reality}
	want := []string{profile.Cloudflare, profile.WireGuard, profile.Hysteria2, profile.Reality}
	if got := aroundFirst(in); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
