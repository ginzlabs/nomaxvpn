package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// reportsSeenKey is the newest report `nomax reports` has shown.
const reportsSeenKey = "reports_seen"

// reports prints what the apps sent with their Send button, by device and in
// the order it happened: what's new since the last look, or with -all
// everything kept.
func reports(args []string) error {
	fs := flag.NewFlagSet("reports", flag.ContinueOnError)
	all := fs.Bool("all", false, "everything kept, not just what's new since the last look")
	since := fs.Duration("since", 0, "only what happened within this long, such as 48h")
	person := fs.String("person", "", "only people whose name contains this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	q := store.ReportQuery{Person: *person}
	if *since > 0 {
		q.Since = time.Now().Add(-*since)
	}
	if !*all {
		seen, _ := st.Setting(reportsSeenKey)
		q.AfterID, _ = strconv.ParseInt(seen, 10, 64)
	}
	rs, err := st.Reports(q)
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		if *all {
			fmt.Println("No reports.")
		} else {
			fmt.Println("Nothing new since the last look. -all shows everything kept.")
		}
		return nil
	}
	fmt.Print(formatReports(rs))
	if !*all {
		newest := int64(0)
		for _, r := range rs {
			newest = max(newest, r.ID)
		}
		return st.SetSetting(reportsSeenKey, strconv.FormatInt(newest, 10))
	}
	return nil
}

// formatReports lays reports out as text: a heading per device with the app
// and where it sent from, then its lines and checks in the order they happened
// (times in UTC, as the device's clock had them).
func formatReports(rs []store.SavedReport) string {
	var b strings.Builder
	for i := 0; i < len(rs); {
		j := i
		for j < len(rs) && rs[j].DeviceID == rs[i].DeviceID {
			j++
		}
		dev, last := rs[i:j], rs[j-1]
		for _, r := range dev {
			if r.Received.After(last.Received) {
				last = r
			}
		}
		lines, checks := 0, 0
		for _, r := range dev {
			if r.Kind == store.ReportCheck {
				checks++
			} else {
				lines++
			}
		}
		fmt.Fprintf(&b, "\n━━ %s · %s (device %d): %s, %s\n", last.Person, last.Device, last.DeviceID, count(lines, "line"), count(checks, "check"))
		fmt.Fprintf(&b, "   %s · sent from %s at %s\n", last.App, last.IP, last.Received.UTC().Format("2 Jan 15:04 UTC"))
		day, run := "", int64(-1)
		for _, r := range dev {
			t := time.UnixMilli(r.T).UTC()
			if d := t.Format("Mon 2 Jan 2006"); d != day {
				day = d
				fmt.Fprintf(&b, "\n%s\n", d)
			}
			if r.Kind == store.ReportCheck {
				fmt.Fprintf(&b, "%s ▣ Connection check\n", t.Format("15:04:05"))
				for line := range strings.SplitSeq(strings.TrimRight(r.Text, "\n"), "\n") {
					fmt.Fprintf(&b, "    %s\n", line)
				}
				run = -1
				continue
			}
			if r.Run != 0 && r.Run != run && r.State != "start" {
				fmt.Fprintf(&b, "%s ┄ run %d continues\n", t.Format("15:04:05"), r.Run)
			}
			if r.Run != 0 {
				run = r.Run
			}
			name := ""
			if r.Proto != "" {
				name = protoTitle(r.Proto) + ": "
			}
			fmt.Fprintf(&b, "%s %s %s%s\n", t.Format("15:04:05"), mark(r.State), name, r.Text)
		}
		i = j
	}
	return b.String()
}

// count is "1 line" or "3 lines".
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func protoTitle(p string) string {
	switch p {
	case "auto":
		return "Auto"
	case "test":
		return "Test"
	}
	return profile.Title(p)
}

// mark is the apps' sign for a step's state.
func mark(state string) string {
	switch state {
	case "ok":
		return "✓"
	case "fail":
		return "✗"
	case "trying":
		return "…"
	case "start":
		return "▶"
	case "done":
		return "■"
	}
	return "·"
}
