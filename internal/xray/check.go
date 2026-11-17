package xray

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// CheckURL is what Check downloads through the tunnel. Some filters let a
// connection pass about 16 KB and then freeze it, so a check has to move more
// than that to mean anything. Tests point it at a local server.
var CheckURL = "https://speed.cloudflare.com/__down?bytes=262144"

// StallTimeout fails a check that stops receiving for this long.
const StallTimeout = 3 * time.Second

// CheckResult is what a passing check measured.
type CheckResult struct {
	FirstByte time.Duration
	Bytes     int64
	// Speed is the body's bytes per second.
	Speed float64
}

// Check downloads CheckURL through the instance over one connection, calling
// progress with each step. It fails at ctx's deadline, or as soon as the
// download stops moving for StallTimeout.
func (i *Instance) Check(ctx context.Context, progress func(string)) (CheckResult, error) {
	return Fetch(ctx, i.Dial, CheckURL, progress)
}

// Fetch is Check with any dialer, so engines outside Xray can share it.
func Fetch(ctx context.Context, dial func(context.Context, string) (net.Conn, error), rawURL string, progress func(string)) (CheckResult, error) {
	var res CheckResult
	if progress == nil {
		progress = func(string) {}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return res, err
	}
	port := u.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[u.Scheme == "https"]
	}
	start := time.Now()
	raw, err := dial(ctx, net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return res, err
	}
	var c net.Conn = &watched{Conn: raw}
	defer c.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = start.Add(30 * time.Second)
	}
	c.SetDeadline(deadline)
	if u.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}})
		if err := tc.HandshakeContext(ctx); err != nil {
			return res, quiet(err, deadline)
		}
		progress(fmt.Sprintf("TLS through the tunnel after %d ms", time.Since(start).Milliseconds()))
		c = tc
	}
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: nomax\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return res, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return res, quiet(err, deadline)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("download answered %d", resp.StatusCode)
	}
	res.FirstByte = time.Since(start)
	progress(fmt.Sprintf("First byte after %d ms", res.FirstByte.Milliseconds()))
	total := resp.ContentLength
	body := time.Now()
	buf := make([]byte, 16<<10)
	next := int64(64 << 10)
	for {
		c.SetReadDeadline(earliest(deadline, time.Now().Add(StallTimeout)))
		n, err := resp.Body.Read(buf)
		res.Bytes += int64(n)
		if res.Bytes >= next && (total <= 0 || res.Bytes < total) {
			progress(fmt.Sprintf("%d of %d KB", res.Bytes>>10, total>>10))
			next += 64 << 10
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if time.Now().Before(deadline) {
					return res, fmt.Errorf("stalled at %d KB", res.Bytes>>10)
				}
				return res, fmt.Errorf("too slow: %d KB in %.0f s", res.Bytes>>10, time.Since(start).Seconds())
			}
			return res, fmt.Errorf("cut off at %d KB: %w", res.Bytes>>10, err)
		}
	}
	if total > 0 && res.Bytes < total {
		return res, fmt.Errorf("cut off at %d KB", res.Bytes>>10)
	}
	if d := time.Since(body).Seconds(); d > 0 {
		res.Speed = float64(res.Bytes) / d
	}
	return res, nil
}

// quiet turns a deadline into a short reason.
func quiet(err error, deadline time.Time) error {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || !time.Now().Before(deadline) {
		return errors.New("no reply through the tunnel")
	}
	return err
}

// watched enforces deadlines by closing the connection when one passes: Xray's
// in-process connections ignore SetDeadline, and a check never reads again
// after a timeout.
type watched struct {
	net.Conn
	mu    sync.Mutex
	timer *time.Timer
	fired atomic.Bool
}

func (w *watched) SetDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
	if !t.IsZero() {
		w.timer = time.AfterFunc(time.Until(t), func() {
			w.fired.Store(true)
			w.Conn.Close()
		})
	}
	return nil
}

func (w *watched) SetReadDeadline(t time.Time) error { return w.SetDeadline(t) }
func (w *watched) SetWriteDeadline(time.Time) error  { return nil }

func (w *watched) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if err != nil && w.fired.Load() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (w *watched) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if err != nil && w.fired.Load() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (w *watched) Close() error {
	w.SetDeadline(time.Time{})
	return w.Conn.Close()
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
