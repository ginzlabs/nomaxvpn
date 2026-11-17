package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestPIN(t *testing.T) {
	if p := NormalizePIN(" 12-34 "); p != "1234" {
		t.Fatalf("NormalizePIN = %q", p)
	}
	if d := RandomDigits(8); len(d) != 8 || NormalizePIN(d) != d {
		t.Fatalf("RandomDigits = %q", d)
	}

	st := open(t)
	p, _ := st.CreatePerson("A", 5)
	first, err := st.NewPIN(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := st.NewPIN(p.ID)
	if len(pin) != PINLength {
		t.Fatalf("pin %q", pin)
	}
	if first != pin {
		if _, _, err := st.Enroll(first, "x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); !errors.Is(err, ErrBadPIN) {
			t.Fatalf("replaced PIN still works: %v", err)
		}
	}
	if got, _ := st.Person(p.ID); got.PIN != pin || got.PINExpires.IsZero() {
		t.Fatalf("person PIN %q %v", got.PIN, got.PINExpires)
	}
	if _, _, err := st.Enroll(pin, "x", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(pin, "x", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); !errors.Is(err, ErrBadPIN) {
		t.Fatalf("PIN worked twice: %v", err)
	}

	pin, _ = st.NewPIN(p.ID)
	st.db.Exec(`UPDATE invites SET expires_at=? WHERE pin=?`, time.Now().Add(-time.Second).Unix(), pin)
	if _, _, err := st.Enroll(pin, "x", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); !errors.Is(err, ErrBadPIN) {
		t.Fatalf("expired PIN worked: %v", err)
	}
	if _, err := st.NewPIN(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PIN for missing person: %v", err)
	}
}

func TestReviewer(t *testing.T) {
	st := open(t)
	for _, bad := range []string{"1234", "12345678"} {
		if err := st.EnsureReviewer("App Review", bad, 2); err == nil {
			t.Fatalf("review PIN %q accepted", bad)
		}
	}
	for range 2 {
		if err := st.EnsureReviewer("App Review", "123456", 2); err != nil {
			t.Fatal(err)
		}
	}
	keys := []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for _, k := range keys {
		if _, _, err := st.Enroll("123-456", "x", k); err != nil {
			t.Fatalf("review PIN should be reusable: %v", err)
		}
	}
	people, _ := st.People()
	if len(people) != 1 || people[0].PIN != "123456" || !people[0].PINExpires.IsZero() {
		t.Fatalf("reviewer %+v", people)
	}
	if _, _, err := st.Enroll("123456", "x", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("a third device: %v", err)
	}
	if err := st.EnsureReviewer("App Review", "123456", 5); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll("123456", "x", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err != nil {
		t.Fatalf("a third device after raising the limit: %v", err)
	}
}

func TestIndexReuse(t *testing.T) {
	st := open(t)
	if err := st.EnsureReviewer("A", "111222", 10); err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	var devs []Device
	for _, k := range keys {
		d, _, err := st.Enroll("111222", "x", k)
		if err != nil {
			t.Fatal(err)
		}
		devs = append(devs, d)
	}
	if devs[0].WGIndex != 2 || devs[2].WGIndex != 4 {
		t.Fatalf("indexes %d..%d", devs[0].WGIndex, devs[2].WGIndex)
	}
	st.DeleteDevice(devs[1].ID)
	d, _, err := st.Enroll("111222", "x", "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	if d.WGIndex != 3 {
		t.Fatalf("freed index not reused: %d", d.WGIndex)
	}
	if d.IPv4() != "10.8.0.3" || d.IPv6() != "fd08::3" {
		t.Fatalf("addresses %s %s", d.IPv4(), d.IPv6())
	}
}
