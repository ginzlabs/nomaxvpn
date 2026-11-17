// Package store keeps people, devices and admin state in one SQLite file.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

// WireGuard device indexes map to 10.8.0.N and fd08::N.
const (
	firstIndex = 2
	lastIndex  = 254
)

type Store struct{ db *sql.DB }

type Person struct {
	ID         int64
	Name       string
	MaxDevices int
	Disabled   bool
	CreatedAt  time.Time
	PIN        string    // active invite PIN, if any
	PINExpires time.Time // zero for a permanent PIN
	Devices    []Device
}

type Device struct {
	ID            int64
	PersonID      int64
	PersonName    string
	Name          string
	WGPublicKey   string
	WGIndex       int
	UUID          string
	HysteriaAuth  string
	CreatedAt     time.Time
	LastSeen      time.Time
	LastHandshake time.Time
	BytesUp       int64
	BytesDown     int64
}

// Email is the device's tag in Xray stats.
func (d Device) Email() string { return fmt.Sprintf("d%d", d.ID) }

func (d Device) IPv4() string { return fmt.Sprintf("10.8.0.%d", d.WGIndex) }
func (d Device) IPv6() string { return fmt.Sprintf("fd08::%x", d.WGIndex) }

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS people (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	max_devices INTEGER NOT NULL DEFAULT 3,
	disabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
	pin TEXT PRIMARY KEY,
	person_id INTEGER NOT NULL UNIQUE REFERENCES people(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY,
	person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	token_hash BLOB NOT NULL UNIQUE,
	wg_public_key TEXT NOT NULL UNIQUE,
	wg_index INTEGER NOT NULL UNIQUE,
	uuid TEXT NOT NULL UNIQUE,
	hy_auth TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL DEFAULT 0,
	last_handshake INTEGER NOT NULL DEFAULT 0,
	bytes_up INTEGER NOT NULL DEFAULT 0,
	bytes_down INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS failures (kind TEXT NOT NULL, ip TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS failures_at ON failures(at);
CREATE TABLE IF NOT EXISTS reports (
	id INTEGER PRIMARY KEY,
	device_id INTEGER NOT NULL,
	person TEXT NOT NULL,
	device TEXT NOT NULL,
	app TEXT NOT NULL,
	ip TEXT NOT NULL,
	kind TEXT NOT NULL,
	t INTEGER NOT NULL,
	run INTEGER NOT NULL,
	proto TEXT NOT NULL,
	state TEXT NOT NULL,
	text TEXT NOT NULL,
	received_at INTEGER NOT NULL,
	key BLOB NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS reports_device ON reports(device_id, t);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- settings ---

func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// --- people ---

func (s *Store) CreatePerson(name string, maxDevices int) (Person, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Person{}, errors.New("name required")
	}
	if maxDevices < 1 {
		maxDevices = 3
	}
	res, err := s.db.Exec(`INSERT INTO people(name,max_devices,created_at) VALUES(?,?,?)`, name, maxDevices, time.Now().Unix())
	if err != nil {
		return Person{}, err
	}
	id, _ := res.LastInsertId()
	return s.Person(id)
}

// EnsureReviewer keeps one person called name whose permanent PIN is pin (the
// App Review account), with room for at least maxDevices devices.
func (s *Store) EnsureReviewer(name, pin string, maxDevices int) error {
	if pin == "" {
		return nil
	}
	if len(pin) != ReviewPINLength || NormalizePIN(pin) != pin {
		return fmt.Errorf("review PIN must be %d digits", ReviewPINLength)
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM people WHERE name=? ORDER BY id LIMIT 1`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		p, err := s.CreatePerson(name, maxDevices)
		if err != nil {
			return err
		}
		id = p.ID
	} else if err != nil {
		return err
	} else if _, err := s.db.Exec(`UPDATE people SET max_devices=? WHERE id=? AND max_devices<?`, maxDevices, id, maxDevices); err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO invites(pin,person_id,expires_at) VALUES(?,?,0)
		ON CONFLICT(person_id) DO UPDATE SET pin=excluded.pin, expires_at=0`, pin, id)
	return err
}

// NewPIN gives a person a fresh single-use PIN valid for PINTTL, replacing any earlier one.
func (s *Store) NewPIN(personID int64) (string, error) {
	now := time.Now()
	if _, err := s.db.Exec(`DELETE FROM invites WHERE expires_at>0 AND expires_at<=?`, now.Unix()); err != nil {
		return "", err
	}
	for range 20 {
		pin := RandomDigits(PINLength)
		_, err := s.db.Exec(`INSERT INTO invites(pin,person_id,expires_at) VALUES(?,?,?)
			ON CONFLICT(person_id) DO UPDATE SET pin=excluded.pin, expires_at=excluded.expires_at`, pin, personID, now.Add(PINTTL).Unix())
		switch {
		case err == nil:
			return pin, nil
		case strings.Contains(err.Error(), "FOREIGN KEY"):
			return "", ErrNotFound
		case !strings.Contains(err.Error(), "UNIQUE"):
			return "", err
		}
	}
	return "", errors.New("no free PIN, try again in a few minutes")
}

func (s *Store) Person(id int64) (Person, error) {
	people, err := s.people(`WHERE p.id=?`, id)
	if err != nil {
		return Person{}, err
	}
	if len(people) == 0 {
		return Person{}, ErrNotFound
	}
	return people[0], nil
}

func (s *Store) People() ([]Person, error) { return s.people(``) }

func (s *Store) people(where string, args ...any) ([]Person, error) {
	rows, err := s.db.Query(`SELECT p.id,p.name,p.max_devices,p.disabled,p.created_at,COALESCE(i.pin,''),COALESCE(i.expires_at,0)
		FROM people p LEFT JOIN invites i ON i.person_id=p.id AND (i.expires_at=0 OR i.expires_at>?) `+where+` ORDER BY p.name COLLATE NOCASE, p.id`,
		append([]any{time.Now().Unix()}, args...)...)
	if err != nil {
		return nil, err
	}
	var out []Person
	idx := map[int64]int{}
	for rows.Next() {
		var p Person
		var created, expires int64
		if err := rows.Scan(&p.ID, &p.Name, &p.MaxDevices, &p.Disabled, &created, &p.PIN, &expires); err != nil {
			rows.Close()
			return nil, err
		}
		p.CreatedAt, p.PINExpires = time.Unix(created, 0), unixOrZero(expires)
		idx[p.ID] = len(out)
		out = append(out, p)
	}
	rows.Close()
	devs, err := s.Devices(false)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if i, ok := idx[d.PersonID]; ok {
			out[i].Devices = append(out[i].Devices, d)
		}
	}
	return out, nil
}

func (s *Store) SetDisabled(id int64, disabled bool) error {
	res, err := s.db.Exec(`UPDATE people SET disabled=? WHERE id=?`, disabled, id)
	if err != nil {
		return err
	}
	return mustAffect(res)
}

func (s *Store) DeletePerson(id int64) error {
	res, err := s.db.Exec(`DELETE FROM people WHERE id=?`, id)
	if err != nil {
		return err
	}
	return mustAffect(res)
}

// --- devices ---

var (
	ErrBadPIN      = errors.New("invalid PIN")
	ErrDeviceLimit = errors.New("device limit reached")
	ErrFull        = errors.New("server is full")
)

// Enroll registers a device for the person holding pin and returns its bearer token.
// A temporary PIN is used up; re-enrolling the same WireGuard key replaces the old device record.
func (s *Store) Enroll(pin, deviceName, wgPublicKey string) (Device, string, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, "", err
	}
	defer tx.Rollback()

	pin = NormalizePIN(pin)
	var personID, expires int64
	var maxDevices int
	var disabled bool
	err = tx.QueryRow(`SELECT p.id,p.max_devices,p.disabled,i.expires_at FROM invites i JOIN people p ON p.id=i.person_id WHERE i.pin=?`, pin).
		Scan(&personID, &maxDevices, &disabled, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (disabled || (expires != 0 && expires <= time.Now().Unix()))) {
		return Device{}, "", ErrBadPIN
	}
	if err != nil {
		return Device{}, "", err
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE wg_public_key=?`, wgPublicKey); err != nil {
		return Device{}, "", err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE person_id=?`, personID).Scan(&count); err != nil {
		return Device{}, "", err
	}
	if count >= maxDevices {
		return Device{}, "", ErrDeviceLimit
	}
	index, err := freeIndex(tx)
	if err != nil {
		return Device{}, "", err
	}
	token := randomToken()
	name := strings.TrimSpace(deviceName)
	if name == "" {
		name = "Device"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	res, err := tx.Exec(`INSERT INTO devices(person_id,name,token_hash,wg_public_key,wg_index,uuid,hy_auth,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?)`,
		personID, name, hashToken(token), wgPublicKey, index, newUUID(), randomToken(), time.Now().Unix(), time.Now().Unix())
	if err != nil {
		return Device{}, "", err
	}
	id, _ := res.LastInsertId()
	if expires != 0 {
		if _, err := tx.Exec(`DELETE FROM invites WHERE pin=?`, pin); err != nil {
			return Device{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return Device{}, "", err
	}
	d, err := s.device(`WHERE d.id=?`, id)
	return d, token, err
}

func freeIndex(tx *sql.Tx) (int, error) {
	rows, err := tx.Query(`SELECT wg_index FROM devices ORDER BY wg_index`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	next := firstIndex
	for rows.Next() {
		var i int
		if err := rows.Scan(&i); err != nil {
			return 0, err
		}
		if i > next {
			break
		}
		if i == next {
			next++
		}
	}
	if next > lastIndex {
		return 0, ErrFull
	}
	return next, nil
}

// DeviceByToken resolves a bearer token. Devices of disabled people are not found.
func (s *Store) DeviceByToken(token string) (Device, error) {
	return s.device(`WHERE d.token_hash=? AND p.disabled=0`, hashToken(token))
}

func (s *Store) device(where string, args ...any) (Device, error) {
	devs, err := s.devices(where, args...)
	if err != nil {
		return Device{}, err
	}
	if len(devs) == 0 {
		return Device{}, ErrNotFound
	}
	return devs[0], nil
}

// Devices lists devices; activeOnly drops those of disabled people.
func (s *Store) Devices(activeOnly bool) ([]Device, error) {
	if activeOnly {
		return s.devices(`WHERE p.disabled=0`)
	}
	return s.devices(``)
}

func (s *Store) devices(where string, args ...any) ([]Device, error) {
	rows, err := s.db.Query(`SELECT d.id,d.person_id,p.name,d.name,d.wg_public_key,d.wg_index,d.uuid,d.hy_auth,d.created_at,d.last_seen,d.last_handshake,d.bytes_up,d.bytes_down
		FROM devices d JOIN people p ON p.id=d.person_id `+where+` ORDER BY d.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var created, seen, hs int64
		if err := rows.Scan(&d.ID, &d.PersonID, &d.PersonName, &d.Name, &d.WGPublicKey, &d.WGIndex, &d.UUID, &d.HysteriaAuth, &created, &seen, &hs, &d.BytesUp, &d.BytesDown); err != nil {
			return nil, err
		}
		d.CreatedAt, d.LastSeen, d.LastHandshake = time.Unix(created, 0), unixOrZero(seen), unixOrZero(hs)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeleteDevice(id int64) error {
	res, err := s.db.Exec(`DELETE FROM devices WHERE id=?`, id)
	if err != nil {
		return err
	}
	return mustAffect(res)
}

func (s *Store) Touch(id int64) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// Usage is a traffic delta for one device.
type Usage struct {
	Up, Down  int64
	Handshake time.Time
}

func (s *Store) AddUsage(u map[int64]Usage) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for id, x := range u {
		seen := int64(0)
		if x.Up+x.Down > 0 {
			seen = now
		}
		if _, err := tx.Exec(`UPDATE devices SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_seen=MAX(last_seen,?), last_handshake=MAX(last_handshake,?) WHERE id=?`,
			x.Up, x.Down, seen, unixOf(x.Handshake), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- admin sessions and lockout ---

func (s *Store) CreateSession(ttl time.Duration) (string, error) {
	token := randomToken()
	_, err := s.db.Exec(`INSERT INTO sessions(token_hash,expires_at) VALUES(?,?)`, hashToken(token), time.Now().Add(ttl).Unix())
	return token, err
}

func (s *Store) ValidSession(token string) bool {
	if token == "" {
		return false
	}
	var exp int64
	err := s.db.QueryRow(`SELECT expires_at FROM sessions WHERE token_hash=?`, hashToken(token)).Scan(&exp)
	return err == nil && exp > time.Now().Unix()
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashToken(token))
	return err
}

// Failure kinds.
const (
	AdminLogin = "admin"
	EnrollPIN  = "enroll"
)

func (s *Store) RecordFailure(kind, ip string) error {
	_, err := s.db.Exec(`INSERT INTO failures(kind,ip,at) VALUES(?,?,?)`, kind, ip, time.Now().Unix())
	return err
}

// Failures counts failures of a kind since t for ip, or for everyone when ip is empty.
func (s *Store) Failures(kind, ip string, since time.Time) (int, error) {
	var n int
	var err error
	if ip == "" {
		err = s.db.QueryRow(`SELECT COUNT(*) FROM failures WHERE kind=? AND at>=?`, kind, since.Unix()).Scan(&n)
	} else {
		err = s.db.QueryRow(`SELECT COUNT(*) FROM failures WHERE kind=? AND ip=? AND at>=?`, kind, ip, since.Unix()).Scan(&n)
	}
	return n, err
}

func (s *Store) ClearFailures(kind string) error {
	_, err := s.db.Exec(`DELETE FROM failures WHERE kind=?`, kind)
	return err
}

// ResetAdmin clears all lockouts and logs out every admin session.
func (s *Store) ResetAdmin() error {
	_, err := s.db.Exec(`DELETE FROM failures; DELETE FROM sessions;`)
	return err
}

func (s *Store) Prune() error {
	now := time.Now()
	_, err := s.db.Exec(`DELETE FROM failures WHERE at<?; DELETE FROM sessions WHERE expires_at<?; DELETE FROM invites WHERE expires_at>0 AND expires_at<?;`,
		now.Add(-24*time.Hour).Unix(), now.Unix(), now.Unix())
	return err
}

// --- helpers ---

// Invite PINs are single-use and short-lived; the App Review PIN is permanent.
// Both have 6 digits, and the invites table keeps them distinct.
const (
	PINLength       = 6
	PINTTL          = 10 * time.Minute
	ReviewPINLength = 6
)

// RandomDigits returns n uniformly random decimal digits.
func RandomDigits(n int) string {
	b := make([]byte, 0, n)
	for len(b) < n {
		var x [1]byte
		rand.Read(x[:])
		if x[0] < 250 {
			b = append(b, '0'+x[0]%10)
		}
	}
	return string(b)
}

// NormalizePIN keeps only the digits.
func NormalizePIN(pin string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, pin)
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func mustAffect(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func unixOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func unixOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
