package xray

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFetchStall serves 256 KB normally, and once frozen after 16 KB the way
// some filters freeze a connection: the check must fail fast, not hang.
func TestFetchStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(256<<10))
		if r.URL.Query().Get("freeze") == "" {
			w.Write(bytes.Repeat([]byte{'x'}, 256<<10))
			return
		}
		w.Write(bytes.Repeat([]byte{'x'}, 16<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	var d net.Dialer
	dial := func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	base := "http://" + ln.Addr().String() + "/"

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var steps []string
	res, err := Fetch(ctx, dial, base, func(s string) { steps = append(steps, s) })
	if err != nil || res.Bytes != 256<<10 || res.Speed <= 0 {
		t.Fatalf("fetch: %+v %v", res, err)
	}
	if len(steps) < 2 || !strings.HasPrefix(steps[0], "First byte") {
		t.Fatalf("steps: %q", steps)
	}

	start := time.Now()
	_, err = Fetch(ctx, dial, base+"?freeze=1", nil)
	if err == nil || !strings.Contains(err.Error(), "stalled at 16 KB") {
		t.Fatalf("frozen fetch: %v", err)
	}
	if took := time.Since(start); took > StallTimeout+time.Second {
		t.Fatalf("stall took %s", took)
	}
}
