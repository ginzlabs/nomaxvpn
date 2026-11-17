package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Device is what joining gave this computer.
type Device struct {
	Host    string          `json:"host"`
	Token   string          `json:"-"`
	WGKey   string          `json:"-"`
	Profile json.RawMessage `json:"profile"`
}

// Settings are the user's choices, kept apart from the device.
type Settings struct {
	Protocol string `json:"protocol"`
	// Route is auto, direct, relay or exit (nomaxcore's Route constants).
	Route string `json:"route,omitempty"`
	// LastGood is the order Auto learned ("worked,…|failed,…"); older
	// versions kept just the protocol that last got through.
	LastGood string `json:"lastGood"`
	// ReportSent is the time (Unix ms) of the newest line or check sent;
	// ReportPending is a Send that couldn't reach the server yet.
	ReportSent    int64 `json:"reportSent"`
	ReportPending bool  `json:"reportPending"`
}

// Store keeps the device and settings in Dir. Seal and Open protect the
// device token and WireGuard key at rest (DPAPI on Windows); nil keeps them as is.
type Store struct {
	Dir        string
	Seal, Open func([]byte) ([]byte, error)
}

type savedDevice struct {
	Device
	Secret []byte `json:"secret"`
}

type secret struct {
	Token string `json:"token"`
	WGKey string `json:"wgKey"`
}

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Device is the saved device, or nil before joining.
func (s Store) Device() (*Device, error) {
	b, err := os.ReadFile(s.path("device.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d savedDevice
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	plain := d.Secret
	if s.Open != nil {
		if plain, err = s.Open(d.Secret); err != nil {
			return nil, err
		}
	}
	var sec secret
	if err := json.Unmarshal(plain, &sec); err != nil {
		return nil, err
	}
	d.Token, d.WGKey = sec.Token, sec.WGKey
	return &d.Device, nil
}

func (s Store) SaveDevice(d Device) error {
	plain, err := json.Marshal(secret{d.Token, d.WGKey})
	if err != nil {
		return err
	}
	if s.Seal != nil {
		if plain, err = s.Seal(plain); err != nil {
			return err
		}
	}
	return s.write("device.json", savedDevice{d, plain})
}

func (s Store) ForgetDevice() error {
	err := os.Remove(s.path("device.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s Store) Settings() Settings {
	var st Settings
	if b, err := os.ReadFile(s.path("settings.json")); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func (s Store) SaveSettings(st Settings) error { return s.write("settings.json", st) }

func (s Store) write(name string, v any) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := s.path(name + ".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(name))
}
