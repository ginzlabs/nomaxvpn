package panel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ginzlabs/nomaxvpn/internal/store"
)

func postReport(t *testing.T, srv *httptest.Server, token, body string) (int, int) {
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/report", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-For", "192.0.2.9")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ New int }
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.New
}

func TestReport(t *testing.T) {
	srv, st, _ := setup(t)
	person, _ := st.CreatePerson("alice", 2)
	code, m := enroll(t, srv, newPIN(t, st, person.ID), wgPub(t))
	if code != http.StatusOK {
		t.Fatalf("enroll: %d", code)
	}
	token := m["deviceToken"].(string)

	first := `{"app":"NoMax 1.0 (40) · Pixel, Android 16",
		"lines":[{"t":1000,"run":7,"proto":"mieru","state":"ok","step":"Works"},{"t":1001,"run":0,"state":"info","step":"Connected"}],
		"checks":[{"t":900,"text":"NoMax connection check\nTLS: times out"}]}`
	if code, n := postReport(t, srv, token, first); code != http.StatusOK || n != 3 {
		t.Fatalf("first report: %d, %d new", code, n)
	}
	again := `{"app":"NoMax 1.0 (40) · Pixel, Android 16",
		"lines":[{"t":1001,"run":0,"state":"info","step":"Connected"},{"t":2000,"run":8,"proto":"cloudflare","state":"fail","step":"stalled"}],
		"checks":[{"t":900,"text":"NoMax connection check\nTLS: times out"}]}`
	if code, n := postReport(t, srv, token, again); code != http.StatusOK || n != 1 {
		t.Fatalf("a report that repeats two: %d, %d new", code, n)
	}
	if code, _ := postReport(t, srv, "not-a-device", first); code != http.StatusUnauthorized {
		t.Fatalf("an unknown device's report: %d", code)
	}
	if code, _ := postReport(t, srv, token, "not json"); code != http.StatusBadRequest {
		t.Fatalf("a malformed report: %d", code)
	}

	rs, err := st.Reports(store.ReportQuery{})
	if err != nil || len(rs) != 4 {
		t.Fatalf("kept %d, %v", len(rs), err)
	}
	if rs[0].Kind != store.ReportCheck || rs[0].Person != "alice" || rs[0].Device != "iPhone" || rs[0].IP != "192.0.2.9" || !strings.Contains(rs[0].App, "Android") {
		t.Fatalf("first kept %+v", rs[0])
	}
	if rs[3].Proto != "cloudflare" || rs[3].Text != "stalled" {
		t.Fatalf("last kept %+v", rs[3])
	}
	newest := rs[3].ID
	if rs, _ := st.Reports(store.ReportQuery{AfterID: newest - 1}); len(rs) != 1 || rs[0].ID != newest {
		t.Fatalf("after all but the newest: %+v", rs)
	}
	if rs, _ := st.Reports(store.ReportQuery{AfterID: newest}); len(rs) != 0 {
		t.Fatalf("after the newest: %d", len(rs))
	}
	if rs, _ := st.Reports(store.ReportQuery{Person: "LIC"}); len(rs) != 4 {
		t.Fatalf("by name: %d", len(rs))
	}
	if rs, _ := st.Reports(store.ReportQuery{Person: "bob"}); len(rs) != 0 {
		t.Fatalf("someone else's: %d", len(rs))
	}

	escapes := `{"lines":[{"t":3000,"state":"info","step":"red \u001b[31mtext\u0007\nfake line"}],
		"checks":[{"t":3001,"text":"a\n\tb\u001b]0;title\u0007"}]}`
	if code, n := postReport(t, srv, token, escapes); code != http.StatusOK || n != 2 {
		t.Fatalf("a report with escapes: %d, %d new", code, n)
	}
	if rs, _ := st.Reports(store.ReportQuery{AfterID: newest}); len(rs) != 2 || rs[0].Text != "red [31mtextfake line" || rs[1].Text != "a\n\tb]0;title" {
		t.Fatalf("escapes kept: %+v", rs)
	}

	dev, _ := st.DeviceByToken(token)
	if err := st.DeleteDevice(dev.ID); err != nil {
		t.Fatal(err)
	}
	if rs, _ := st.Reports(store.ReportQuery{}); len(rs) != 6 {
		t.Fatalf("reports after removing the device: %d", len(rs))
	}
}
