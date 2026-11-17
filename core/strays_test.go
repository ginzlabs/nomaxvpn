package nomaxcore

import "testing"

func TestCloseStrays(t *testing.T) {
	cfg := []byte(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom"}]}`)
	start := func() {
		t.Helper()
		if _, err := startXray(cfg); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	saved := xr
	defer func() { xr = saved }()

	start()
	start()
	kept, err := startXray(cfg)
	if err != nil {
		t.Fatal(err)
	}
	xr = kept
	if n := closeStrays(); n != 2 {
		t.Fatalf("closed %d, want the 2 besides the current one", n)
	}
	if !running[kept] {
		t.Fatal("the current instance was closed")
	}
	closeXray(kept)
	if n := closeStrays(); n != 0 || len(running) != 0 {
		t.Fatalf("closed %d, %d still running", n, len(running))
	}
}
