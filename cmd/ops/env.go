package main

import (
	"fmt"
	"os"
	"strings"
)

// envPath is _cert/nomax.env; NOMAX_ENV_FILE points ops at another server's
// config (such as the previous domain's while both run).
var envPath = func() string {
	if p := os.Getenv("NOMAX_ENV_FILE"); p != "" {
		return p
	}
	return "_cert/nomax.env"
}()

// Env is _cert/nomax.env, kept in file order so rewrites preserve comments.
type Env struct {
	lines []string
	vals  map[string]string
}

func loadEnv() (*Env, error) {
	e := &Env{vals: map[string]string{}}
	b, err := os.ReadFile(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			ex, err2 := os.ReadFile("_cert/nomax.example.env")
			if err2 != nil {
				return nil, err
			}
			b = ex
		} else {
			return nil, err
		}
	}
	e.lines = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for _, l := range e.lines {
		if k, v, ok := parseLine(l); ok {
			e.vals[k] = v
		}
	}
	// The file wins over the environment, which only fills what the file
	// leaves empty (Get): a shell exporting another project's
	// CLOUDFLARE_API_TOKEN must not send changes to that project.
	return e, nil
}

func parseLine(l string) (string, string, bool) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") {
		return "", "", false
	}
	k, v, ok := strings.Cut(l, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`), true
}

func (e *Env) Get(k string) string {
	if v, ok := e.vals[k]; ok && v != "" {
		return v
	}
	return os.Getenv(k)
}

func (e *Env) Must(k string) string {
	v := e.Get(k)
	if v == "" {
		fatalf("%s is not set in %s", k, envPath)
	}
	return v
}

func (e *Env) Set(k, v string) {
	e.vals[k] = v
	for i, l := range e.lines {
		if key, _, ok := parseLine(l); ok && key == k {
			e.lines[i] = k + "=" + v
			return
		}
	}
	e.lines = append(e.lines, k+"="+v)
}

func (e *Env) Save() error {
	return os.WriteFile(envPath, []byte(strings.Join(e.lines, "\n")+"\n"), 0o600)
}

// serverKeys are the values the server receives in /etc/nomax/nomax.env.
var serverKeys = []string{"DOMAIN", "ADMIN_PATH", "API_PATH", "FILES_PATH", "PRIVACY_PATH", "REVIEW_CODE", "REALITY_PRIVATE_KEY", "REALITY_SHORT_ID", "WG_PRIVATE_KEY", "TESTFLIGHT_URL", "RELAYS", "MOVED_TO"}

func (e *Env) serverEnv() string {
	var b strings.Builder
	for _, k := range serverKeys {
		fmt.Fprintf(&b, "%s=%s\n", k, e.Get(k))
	}
	return b.String()
}
