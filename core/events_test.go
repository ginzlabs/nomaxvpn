package nomaxcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestEvents(t *testing.T) {
	r := newRun([]string{"s3cret-password"})
	emit(r, profile.Mieru, stateFail, "login s3cret-password refused")
	emit(r-1, profile.Mieru, stateOK, "from an old run")
	var got []event
	if err := json.Unmarshal([]byte(Events(0)), &got); err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Run != r || last.State != stateFail || strings.Contains(last.Step, "s3cret") {
		t.Fatalf("last event %+v", last)
	}
	if Events(last.Seq) != "[]" {
		t.Fatalf("events after the last: %s", Events(last.Seq))
	}
	for range maxEvents + 10 {
		emit(r, "", stateInfo, "x")
	}
	if err := json.Unmarshal([]byte(Events(0)), &got); err != nil || len(got) != maxEvents {
		t.Fatalf("kept %d events, %v", len(got), err)
	}
}

func TestAutoOrder(t *testing.T) {
	p := profile.Profile{WireGuard: profile.WireGuardConf{ServerPublicKey: "x"}, AmneziaWG: &profile.AmneziaConf{}, Mieru: &profile.MieruConf{Port: 2096}}
	got := autoOrder(p, profile.Reality)
	want := []string{profile.Reality, profile.WireGuard, profile.AmneziaWG, profile.Mieru}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order %v, want %v", got, want)
	}
	if got := autoOrder(p, profile.Hysteria2); got[0] != profile.WireGuard {
		t.Fatalf("a preferred protocol the server lacks went first: %v", got)
	}
}

func TestReasonOnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if got := reason(overdue(ctx, io.ErrClosedPipe), 8*time.Second); got != "no answer within 8 s" {
		t.Fatalf("reason %q", got)
	}
	if got := reason(overdue(context.Background(), io.ErrClosedPipe), 8*time.Second); got != io.ErrClosedPipe.Error() {
		t.Fatalf("reason %q", got)
	}
	handshake := errors.New("no handshake: the server's replies don't arrive")
	if got := reason(overdue(ctx, handshake), 3*time.Second); got != handshake.Error() {
		t.Fatalf("a check's own reason was replaced: %q", got)
	}
}
