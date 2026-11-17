package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

func TestFormatReports(t *testing.T) {
	at := time.Date(2026, 11, 13, 16, 19, 3, 0, time.UTC).UnixMilli()
	dev := func(r store.Report) store.SavedReport {
		return store.SavedReport{Report: r, DeviceID: 5, Person: "alice", Device: "S25", App: "NoMax 1.0 (40) · S25, Android 16", IP: "192.0.2.9", Received: time.Unix(at/1000+60, 0)}
	}
	out := formatReports([]store.SavedReport{
		dev(store.Report{Kind: store.ReportCheck, T: at, Text: "NoMax connection check\nTLS: times out\n"}),
		dev(store.Report{Kind: store.ReportLog, T: at + 1000, Run: 7, Proto: "auto", State: "start", Text: "Trying 12 protocols"}),
		dev(store.Report{Kind: store.ReportLog, T: at + 2000, State: "info", Text: "Connection check started"}),
		dev(store.Report{Kind: store.ReportLog, T: at + 3000, Run: 7, Proto: "cloudflare", State: "ok", Text: "Works"}),
	})
	for _, want := range []string{
		"━━ alice · S25 (device 5): 3 lines, 1 check",
		"sent from 192.0.2.9 at 13 Nov 16:20 UTC",
		"Fri 13 Nov 2026",
		"16:19:03 ▣ Connection check\n    NoMax connection check\n    TLS: times out\n",
		"16:19:04 ▶ Auto: Trying 12 protocols",
		"16:19:05 · Connection check started",
		"16:19:06 ✓ Cloudflare: Works",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
