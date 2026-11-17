package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/directory"
)

// cmdPublish puts the directory (internal/directory) where apps look when
// every way they know has failed: the server's name, addresses and relays,
// signed and encrypted, in a DNS TXT record and a secret gist. The first run
// makes the keys and the gist; apps built after that carry them.
func cmdPublish(env *Env, _ []string) {
	fresh := ensureDirectoryKeys(env)
	seed, _ := base64.StdEncoding.DecodeString(env.Must("DIRECTORY_SIGN"))
	secret, _ := base64.StdEncoding.DecodeString(env.Must("DIRECTORY_SECRET"))
	e := directory.Entry{T: time.Now().Unix(), Host: env.Must("DOMAIN"), Relays: relays(env)}
	for _, k := range []string{"ipv4", "ipv6"} {
		if ip := tofuOutput(env, k); ip != "" {
			e.IPs = append(e.IPs, ip)
		}
	}
	if len(e.IPs) == 0 {
		e.IPs = []string{serverIPv4(env)}
	}
	blob, err := directory.Seal(e, ed25519.NewKeyFromSeed(seed), secret)
	if err != nil {
		fatalf("sealing the directory: %v", err)
	}
	step("publishing %s with %d addresses and %d relays", e.Host, len(e.IPs), len(e.Relays))
	cloudflareTXT(env, env.Must("DIRECTORY_NAME"), directory.TXT(blob))
	if publishGist(env, blob) {
		fresh = true
	}
	if err := env.Save(); err != nil {
		fatalf("%v", err)
	}
	if fresh && exec.Command("gh", "secret", "list").Run() == nil {
		cmdGHSecrets(env, nil)
	}

	directory.PublicKey, directory.Secret = env.Get("DIRECTORY_PUBLIC"), env.Get("DIRECTORY_SECRET")
	directory.Name, directory.GistURL = env.Get("DIRECTORY_NAME"), env.Get("DIRECTORY_GIST")
	for range 12 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, err := directory.Lookup(ctx)
		cancel()
		if err == nil && got.T == e.T {
			step("the directory answers with this entry")
			return
		}
		time.Sleep(10 * time.Second)
	}
	step("published; the directory still answers with an older entry (DNS and the gist can take a few minutes)")
}

// ensureDirectoryKeys makes the directory's keys and record name once.
func ensureDirectoryKeys(env *Env) bool {
	made := false
	if env.Get("DIRECTORY_SIGN") == "" || env.Get("DIRECTORY_PUBLIC") == "" {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		env.Set("DIRECTORY_SIGN", base64.StdEncoding.EncodeToString(priv.Seed()))
		env.Set("DIRECTORY_PUBLIC", base64.StdEncoding.EncodeToString(pub))
		made = true
	}
	if env.Get("DIRECTORY_SECRET") == "" {
		k := make([]byte, 32)
		rand.Read(k)
		env.Set("DIRECTORY_SECRET", base64.StdEncoding.EncodeToString(k))
		made = true
	}
	if env.Get("DIRECTORY_NAME") == "" {
		env.Set("DIRECTORY_NAME", randomString("abcdefghijklmnopqrstuvwxyz0123456789", 10)+"."+env.Must("DOMAIN"))
		made = true
	}
	if made {
		step("generated the directory's keys")
	}
	return made
}

// cloudflareTXT creates or replaces the TXT record name in the zone.
func cloudflareTXT(env *Env, name, content string) {
	zone := env.Must("CLOUDFLARE_ZONE_ID")
	call := func(method, path string, body any) json.RawMessage {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, "https://api.cloudflare.com/client/v4/zones/"+zone+path, rd)
		req.Header.Set("Authorization", "Bearer "+env.Must("CLOUDFLARE_API_TOKEN"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fatalf("Cloudflare: %v", err)
		}
		defer resp.Body.Close()
		var out struct {
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		if !out.Success {
			var msgs []string
			for _, e := range out.Errors {
				msgs = append(msgs, e.Message)
			}
			fatalf("Cloudflare %s %s: %d %s", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.Join(msgs, "; "))
		}
		return out.Result
	}
	var existing []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(call("GET", "/dns_records?type=TXT&name="+url.QueryEscape(name), nil), &existing)
	record := map[string]any{"type": "TXT", "name": name, "content": content, "ttl": 300}
	if len(existing) > 0 {
		call("PUT", "/dns_records/"+existing[0].ID, record)
	} else {
		call("POST", "/dns_records", record)
	}
	step("DNS TXT record updated")
}

// publishGist writes blob to the secret gist, making it the first time.
func publishGist(env *Env, blob string) (created bool) {
	dir, err := os.MkdirTemp("", "nomax-publish")
	if err != nil {
		fatalf("%v", err)
	}
	defer os.RemoveAll(dir)
	name := env.Get("DIRECTORY_GIST_FILE")
	if name == "" {
		name = randomString("abcdefghijklmnopqrstuvwxyz0123456789", 8) + ".txt"
	}
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(blob+"\n"), 0o600); err != nil {
		fatalf("%v", err)
	}
	if id := env.Get("DIRECTORY_GIST_ID"); id != "" {
		if err := runErr(nil, "gh", "gist", "edit", id, "--filename", name, file); err != nil {
			fatalf("gist: %v", err)
		}
		step("gist updated")
		return false
	}
	out, err := exec.Command("gh", "gist", "create", file).Output()
	if err != nil {
		fatalf("gist: %v", err)
	}
	gistURL := strings.TrimSpace(string(out))
	id := gistURL[strings.LastIndex(gistURL, "/")+1:]
	owner, err := exec.Command("gh", "api", "user", "-q", ".login").Output()
	if err != nil || id == "" {
		fatalf("gist: can't tell its address (%v)", err)
	}
	env.Set("DIRECTORY_GIST_ID", id)
	env.Set("DIRECTORY_GIST_FILE", name)
	env.Set("DIRECTORY_GIST", fmt.Sprintf("https://gist.githubusercontent.com/%s/%s/raw/%s", strings.TrimSpace(string(owner)), id, name))
	step("gist created")
	return true
}
