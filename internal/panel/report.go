package panel

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

// What an app may send in one report, and how often.
const (
	reportMaxBody   = 4 << 20
	reportMaxLines  = 5000
	reportMaxChecks = 50
	reportMaxStep   = 2000
	reportMaxCheck  = 64 << 10
	reportPerHour   = 60
)

// reportReq is POST {API}/report: the log lines and connection checks an
// app hasn't sent yet (it may send some again; they're kept once).
type reportReq struct {
	App   string `json:"app"`
	Lines []struct {
		T     int64  `json:"t"`
		Run   int64  `json:"run"`
		Proto string `json:"proto"`
		State string `json:"state"`
		Step  string `json:"step"`
	} `json:"lines"`
	Checks []struct {
		T    int64  `json:"t"`
		Text string `json:"text"`
	} `json:"checks"`
}

func (p *Panel) postReport(w http.ResponseWriter, r *http.Request, d store.Device) {
	if !p.reportLimit.allow(d.ID, reportPerHour, time.Hour) {
		jsonErr(w, http.StatusTooManyRequests, "That's a lot of reports. Try again in an hour.")
		return
	}
	var req reportReq
	if err := json.NewDecoder(io.LimitReader(r.Body, reportMaxBody)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "Bad report.")
		return
	}
	if len(req.Lines) > reportMaxLines || len(req.Checks) > reportMaxChecks {
		jsonErr(w, http.StatusRequestEntityTooLarge, "The report is too long.")
		return
	}
	var rs []store.Report
	for _, l := range req.Lines {
		rs = append(rs, store.Report{Kind: store.ReportLog, T: l.T, Run: l.Run,
			Proto: clean(l.Proto, 40, false), State: clean(l.State, 20, false), Text: clean(l.Step, reportMaxStep, false)})
	}
	for _, c := range req.Checks {
		rs = append(rs, store.Report{Kind: store.ReportCheck, T: c.T, Text: clean(c.Text, reportMaxCheck, true)})
	}
	added, err := p.st.AddReports(d, clean(req.App, 200, false), ClientIP(r), rs)
	if err != nil {
		p.log.Error("report", "device", d.ID, "err", err)
		jsonErr(w, http.StatusInternalServerError, "Server error.")
		return
	}
	p.log.Info("report", "device", d.ID, "sent", len(rs), "new", added)
	writeJSON(w, http.StatusOK, map[string]int{"new": added})
}

// clean drops control characters and invalid UTF-8, which would otherwise
// reach the terminal of whoever reads `nomax reports`; multi-line text keeps
// its newlines and tabs. Then it cuts s to at most n bytes.
func clean(s string, n int, multiline bool) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case multiline && (r == '\n' || r == '\t'):
			return r
		case unicode.IsControl(r), r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	return clip(s, n)
}

// clip cuts s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// rateLimit counts requests per key in a sliding window.
type rateLimit struct {
	mu   sync.Mutex
	seen map[int64][]time.Time
}

func (l *rateLimit) allow(key int64, n int, per time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[int64][]time.Time{}
	}
	now := time.Now()
	recent := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < per {
			recent = append(recent, t)
		}
	}
	if len(recent) >= n {
		l.seen[key] = recent
		return false
	}
	l.seen[key] = append(recent, now)
	return true
}
