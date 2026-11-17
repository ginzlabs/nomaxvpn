package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// reports is a server whose own name never answers; its website does once web is set.
type reports struct {
	mu  sync.Mutex
	web bool
	got []Report
}

func (s *reports) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Host != "web.vpn.test" || !s.web {
		return nil, errors.New("connection refused")
	}
	if r.URL.Path != "/api/v1/report" || r.Header.Get("Authorization") != "Bearer tok" {
		return nil, fmt.Errorf("unexpected %s %s", r.Method, r.URL)
	}
	var rep Report
	json.NewDecoder(r.Body).Decode(&rep)
	s.got = append(s.got, rep)
	w := httptest.NewRecorder()
	json.NewEncoder(w).Encode(map[string]int{"new": len(rep.Lines) + len(rep.Checks)})
	return w.Result(), nil
}

func TestSend(t *testing.T) {
	dir := t.TempDir()
	srv := &reports{}
	a := &App{store: Store{Dir: dir}, log: openLog(filepath.Join(dir, "log.jsonl")),
		device:   &Device{Host: "vpn.test", Token: "tok"},
		platform: Platform{Info: "NoMax test", Client: &http.Client{Transport: srv}}}
	send := func(start func()) SendState {
		start()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			a.mu.Lock()
			st := a.send
			a.mu.Unlock()
			if !st.Sending {
				return st
			}
		}
		t.Fatal("still sending")
		return SendState{}
	}
	a.logApp("Opened")
	for i := range checksKept + 2 {
		a.store.AddCheck(SavedCheck{T: int64(i + 1), Text: fmt.Sprintf("check %d", i)})
	}

	if st := send(a.Send); !strings.Contains(st.Message, "Can't reach") || !a.store.Settings().ReportPending {
		t.Fatalf("unreachable: %+v, %+v", st, a.store.Settings())
	}
	srv.mu.Lock()
	srv.web = true
	srv.mu.Unlock()
	if st := send(a.sendIfPending); !strings.HasPrefix(st.Message, "Sent") || a.store.Settings().ReportPending {
		t.Fatalf("through the website: %+v, %+v", st, a.store.Settings())
	}
	if len(srv.got) != 1 || len(srv.got[0].Lines) != 1 || len(srv.got[0].Checks) != checksKept ||
		srv.got[0].Checks[0].Text != "check 2" || srv.got[0].App != "NoMax test" {
		t.Fatalf("sent %+v", srv.got)
	}

	if st := send(a.Send); !strings.Contains(st.Message, "sent already") || len(srv.got) != 1 {
		t.Fatalf("nothing new: %+v, %d reports", st, len(srv.got))
	}
	time.Sleep(2 * time.Millisecond)
	a.logApp("Connected")
	send(a.Send)
	if len(srv.got) != 2 || len(srv.got[1].Lines) != 1 || srv.got[1].Lines[0].Step != "Connected" || len(srv.got[1].Checks) != 0 {
		t.Fatalf("second send %+v", srv.got)
	}
}
