package store

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// What the apps send when someone taps Send: their log's lines and the
// connection checks they ran. Reports outlive the device that sent them, so
// they keep its names.
const (
	ReportLog   = "log"
	ReportCheck = "check"

	// reportsKept is how many a device's reports are kept, newest first, and
	// reportsMaxAge how long.
	reportsKept   = 20000
	reportsMaxAge = 180 * 24 * time.Hour
)

// Report is one line of an app's log (Kind ReportLog: its run, protocol,
// state and step) or a connection check (Kind ReportCheck: the report in Text).
type Report struct {
	Kind  string
	T     int64 // Unix milliseconds, on the device's clock
	Run   int64
	Proto string
	State string
	Text  string
}

// SavedReport is a report as kept, with who sent it, from where and when.
type SavedReport struct {
	Report
	ID       int64
	DeviceID int64
	Person   string
	Device   string
	App      string
	IP       string
	Received time.Time
}

// AddReports keeps what d sent and returns how many weren't kept already.
func (s *Store) AddReports(d Device, app, ip string, rs []Report) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now()
	added := 0
	for _, r := range rs {
		key := sha256.Sum256(fmt.Appendf(nil, "%d\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s", d.ID, r.Kind, r.T, r.Run, r.Proto, r.State, r.Text))
		res, err := tx.Exec(`INSERT OR IGNORE INTO reports(device_id,person,device,app,ip,kind,t,run,proto,state,text,received_at,key)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			d.ID, d.PersonName, d.Name, app, ip, r.Kind, r.T, r.Run, r.Proto, r.State, r.Text, now.Unix(), key[:16])
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		added += int(n)
	}
	if _, err := tx.Exec(`DELETE FROM reports WHERE device_id=? AND (received_at<? OR id NOT IN
		(SELECT id FROM reports WHERE device_id=? ORDER BY id DESC LIMIT ?))`,
		d.ID, now.Add(-reportsMaxAge).Unix(), d.ID, reportsKept); err != nil {
		return 0, err
	}
	return added, tx.Commit()
}

// ReportQuery picks reports: received after AfterID, from events since Since
// (if set), from people whose name contains Person (if set).
type ReportQuery struct {
	AfterID int64
	Since   time.Time
	Person  string
}

// Reports are the reports q picks, by device and then in the order they happened.
func (s *Store) Reports(q ReportQuery) ([]SavedReport, error) {
	since := int64(0)
	if !q.Since.IsZero() {
		since = q.Since.UnixMilli()
	}
	rows, err := s.db.Query(`SELECT id,device_id,person,device,app,ip,kind,t,run,proto,state,text,received_at FROM reports
		WHERE id>? AND t>=? AND (?='' OR instr(lower(person), lower(?))>0)
		ORDER BY device_id, t, id`, q.AfterID, since, q.Person, q.Person)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedReport
	for rows.Next() {
		var r SavedReport
		var received int64
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.Person, &r.Device, &r.App, &r.IP, &r.Kind, &r.T, &r.Run, &r.Proto, &r.State, &r.Text, &received); err != nil {
			return nil, err
		}
		r.Received = time.Unix(received, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}
