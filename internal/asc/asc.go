// Package asc is a small App Store Connect API client (ES256 JWT auth).
package asc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const api = "https://api.appstoreconnect.apple.com"

type Client struct {
	keyID, issuer string
	key           *ecdsa.PrivateKey
	token         string
	minted        time.Time
	http          *http.Client
}

func New(keyID, issuer string, p8 []byte) (*Client, error) {
	b, _ := pem.Decode(p8)
	if b == nil {
		return nil, errors.New("asc: key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("asc: key is not ECDSA")
	}
	return &Client{keyID: keyID, issuer: issuer, key: ec, http: &http.Client{Timeout: 60 * time.Second}}, nil
}

func (c *Client) jwt() (string, error) {
	if c.token != "" && time.Since(c.minted) < 10*time.Minute {
		return c.token, nil
	}
	enc := base64.RawURLEncoding
	now := time.Now().Unix()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID, "typ": "JWT"})
	p, _ := json.Marshal(map[string]any{"iss": c.issuer, "iat": now, "exp": now + 900, "aud": "appstoreconnect-v1"})
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	c.token, c.minted = signing+"."+enc.EncodeToString(sig), time.Now()
	return c.token, nil
}

// Resource is a JSON:API resource object.
type Resource struct {
	Type          string                     `json:"type"`
	ID            string                     `json:"id,omitempty"`
	Attributes    map[string]any             `json:"attributes,omitempty"`
	Relationships map[string]json.RawMessage `json:"relationships,omitempty"`
}

func (r Resource) Str(attr string) string {
	if v, ok := r.Attributes[attr].(string); ok {
		return v
	}
	return ""
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string { return fmt.Sprintf("asc: %d %s", e.Status, e.Body) }

// Do sends a request; out may be nil.
func (c *Client) Do(method, path string, body, out any) error {
	url := path
	if !strings.HasPrefix(path, "http") {
		url = api + path
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.jwt()
		if err != nil {
			return err
		}
		req, _ := http.NewRequest(method, url, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < 4 {
				time.Sleep(time.Duration(2<<attempt) * time.Second)
				continue
			}
			return err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < 5 {
			time.Sleep(time.Duration(2<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode >= 300 {
			return &Error{Status: resp.StatusCode, Body: summarize(data)}
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
}

func summarize(data []byte) string {
	var e struct {
		Errors []struct{ Code, Title, Detail string }
	}
	if json.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
		var parts []string
		for _, x := range e.Errors {
			parts = append(parts, x.Code+": "+x.Detail)
		}
		return strings.Join(parts, "; ")
	}
	return string(data)
}

// List follows pagination and returns every resource.
func (c *Client) List(path string) ([]Resource, error) {
	var all []Resource
	for path != "" {
		var page struct {
			Data  []Resource
			Links struct{ Next string }
		}
		if err := c.Do("GET", path, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		path = page.Links.Next
	}
	return all, nil
}

// Create POSTs a resource and returns the created object.
func (c *Client) Create(path, typ string, attrs map[string]any, rels map[string]any) (Resource, error) {
	data := map[string]any{"type": typ}
	if attrs != nil {
		data["attributes"] = attrs
	}
	if rels != nil {
		r := map[string]any{}
		for k, v := range rels {
			r[k] = map[string]any{"data": v}
		}
		data["relationships"] = r
	}
	var out struct{ Data Resource }
	err := c.Do("POST", path, map[string]any{"data": data}, &out)
	return out.Data, err
}

// Update PATCHes attributes on a resource.
func (c *Client) Update(path, typ, id string, attrs map[string]any) error {
	return c.Do("PATCH", path, map[string]any{"data": map[string]any{"type": typ, "id": id, "attributes": attrs}}, nil)
}

// Ref is a relationship linkage.
func Ref(typ, id string) map[string]string { return map[string]string{"type": typ, "id": id} }
