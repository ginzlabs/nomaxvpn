// Package desktop is the Windows app without its window: joining, the saved
// device, connecting through the core, the log, the IP check and the
// connection check. The window (windows/) and the Mac preview
// (windows/preview) show it through the same page, ui/index.html.
package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/ginzlabs/nomaxvpn/internal/apiclient"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// APIError is the server's answer to a request it refused.
type APIError struct {
	Msg          string
	Unauthorized bool
}

func (e *APIError) Error() string { return e.Msg }

// API is the device API at https://host plus profile.API(), reached through
// the server's address, a relay or Cloudflare (internal/apiclient).
type API struct {
	Host       string
	Relays     []string
	RelayFirst bool
	// Client, when set, makes every request instead (the tests, the preview).
	Client *http.Client
}

// Enroll joins with a PIN and returns the device token and profile.
func (a API) Enroll(ctx context.Context, pin, deviceName, wgPublicKey string) (string, json.RawMessage, error) {
	var out struct {
		DeviceToken string          `json:"deviceToken"`
		Profile     json.RawMessage `json:"profile"`
	}
	err := a.call(ctx, "POST", "enroll", "", map[string]string{"pin": pin, "deviceName": deviceName, "wgPublicKey": wgPublicKey}, &out)
	if err == nil && (out.DeviceToken == "" || len(out.Profile) == 0) {
		err = errors.New("the server's answer is incomplete")
	}
	return out.DeviceToken, out.Profile, err
}

// Profile is the device's current profile.
func (a API) Profile(ctx context.Context, token string) (json.RawMessage, error) {
	var out json.RawMessage
	err := a.call(ctx, "GET", "profile", token, nil, &out)
	return out, err
}

// DeleteDevice removes this device from the server.
func (a API) DeleteDevice(ctx context.Context, token string) error {
	return a.call(ctx, "DELETE", "device", token, nil, nil)
}

// Report sends log lines and connection checks; the server keeps each once
// and says how many were new.
func (a API) Report(ctx context.Context, token string, r Report) (int, error) {
	var out struct {
		New int `json:"new"`
	}
	err := a.call(ctx, "POST", "report", token, r, &out)
	return out.New, err
}

func (a API) call(ctx context.Context, method, path, token string, body, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	status, text, err := a.send(ctx, method, path, token, b)
	if err != nil {
		return fmt.Errorf("can't reach %s: %w", a.Host, err)
	}
	if status/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := fmt.Sprintf("Server error (%d).", status)
		if json.Unmarshal(text, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &APIError{Msg: msg, Unauthorized: status == http.StatusUnauthorized}
	}
	if out == nil || len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], text...)
		return nil
	}
	return json.Unmarshal(text, out)
}

func (a API) send(ctx context.Context, method, path, token string, body []byte) (int, []byte, error) {
	if a.Client == nil {
		r, err := apiclient.Client{Host: a.Host, Relays: a.Relays, RelayFirst: a.RelayFirst}.Do(ctx, method, path, token, body)
		return r.Status, []byte(r.Body), err
	}
	status, text, err := a.sendTo(ctx, a.Host, method, path, token, body)
	if err != nil && net.ParseIP(a.Host) == nil && ctx.Err() == nil {
		if s, t, werr := a.sendTo(ctx, "web."+a.Host, method, path, token, body); werr == nil {
			return s, t, nil
		}
	}
	return status, text, err
}

func (a API) sendTo(ctx context.Context, host, method, path, token string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+profile.API()+"/"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, text, err
}

// firstLine is an error as one line, for the window.
func firstLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return s
}
