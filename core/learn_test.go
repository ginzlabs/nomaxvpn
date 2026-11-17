package nomaxcore

import (
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestLearnedOrder(t *testing.T) {
	p := profile.Profile{
		WireGuard: profile.WireGuardConf{ServerPublicKey: "x"},
		AmneziaWG: &profile.AmneziaConf{},
		Hysteria2: &profile.HysteriaConf{Obfs: &profile.HysteriaObfs{}},
		Mieru:     &profile.MieruConf{},
	}
	o := parseOrder(profile.Hysteria2) // what apps kept before
	o.failed(profile.WireGuard)
	o.failed(profile.AmneziaWG)
	o.worked(profile.Reality)
	if got, want := o.String(), "reality,hysteria2|wireguard,amneziawg"; got != want {
		t.Fatalf("learned %q, want %q", got, want)
	}
	got := strings.Join(autoOrder(p, o.String()), ",")
	if want := "reality,hysteria2,hysteria2obfs,mieru,wireguard,amneziawg"; got != want {
		t.Fatalf("order %s, want %s", got, want)
	}
	if got := lastTitles(autoOrder(p, o.String()), o.String()); strings.Join(got, ",") != "WireGuard,AmneziaWG" {
		t.Fatalf("last %v", got)
	}

	o.worked(profile.WireGuard)
	if got, want := o.String(), "wireguard,reality,hysteria2|amneziawg"; got != want {
		t.Fatalf("after WireGuard worked again: %q, want %q", got, want)
	}
	o.failed(profile.Reality)
	if got, want := o.String(), "wireguard,hysteria2|amneziawg,reality"; got != want {
		t.Fatalf("after Reality failed: %q, want %q", got, want)
	}
	if got := parseOrder(" mieru , mieru ,|").String(); got != "mieru|" {
		t.Fatalf("parsed %q", got)
	}
	if got := parseOrder("").String(); got != "" {
		t.Fatalf("nothing learned reads %q", got)
	}
}

func TestLearnInProcess(t *testing.T) {
	learnMu.Lock()
	saved := learned
	learned = order{}
	learnMu.Unlock()
	t.Cleanup(func() {
		learnMu.Lock()
		learned = saved
		learnMu.Unlock()
	})

	learnFrom("reality|wireguard")
	learnFrom("mieru") // the app's copy is older than what the process learned
	learnFailed(profile.Reality)
	learnQuickest(map[string]time.Duration{profile.Mieru: 3 * time.Second, profile.Hysteria2: time.Second, profile.AnyTLS: 2 * time.Second})
	if got, want := Preferred(), "hysteria2,anytls,mieru|wireguard,reality"; got != want {
		t.Fatalf("learned %q, want %q", got, want)
	}
}
