package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"github.com/ginzlabs/nomaxvpn/internal/vpn"
)

const (
	sshKey     = "_cert/ssh_ed25519"
	knownHosts = "_cert/known_hosts"
)

// stateTgz keeps the server's people, devices and keys between down and up.
// Another config (NOMAX_ENV_FILE) has its own, so taking the old server down
// doesn't overwrite the current one's.
var stateTgz = func() string {
	if envPath == "_cert/nomax.env" {
		return "_cert/state.tgz"
	}
	return strings.TrimSuffix(envPath, ".env") + ".state.tgz"
}()

func randomString(alphabet string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newAdminCode() string { return randomString("abcdefghijkmnpqrstuvwxyz23456789", 24) }

func cmdInit(env *Env, _ []string) {
	gen := map[string]func() string{
		"ADMIN_CODE":          newAdminCode,
		"ADMIN_PATH":          func() string { return randomString("abcdefghijklmnopqrstuvwxyz0123456789", 20) },
		"API_PATH":            func() string { return randomString("abcdefghijklmnopqrstuvwxyz0123456789", 16) },
		"FILES_PATH":          func() string { return randomString("abcdefghijkmnpqrstuvwxyz23456789", 12) },
		"PRIVACY_PATH":        func() string { return randomString("abcdefghijklmnopqrstuvwxyz0123456789", 16) },
		"REVIEW_CODE":         func() string { return store.RandomDigits(store.ReviewPINLength) },
		"REALITY_PRIVATE_KEY": profile.NewRealityKey,
		"REALITY_SHORT_ID":    func() string { return profile.RandomHex(8) },
		"WG_PRIVATE_KEY":      profile.NewWireGuardKey,
	}
	for _, k := range []string{"ADMIN_CODE", "ADMIN_PATH", "API_PATH", "FILES_PATH", "PRIVACY_PATH", "REVIEW_CODE", "REALITY_PRIVATE_KEY", "REALITY_SHORT_ID", "WG_PRIVATE_KEY"} {
		if env.Get(k) == "" {
			env.Set(k, gen[k]())
			step("generated %s", k)
		}
	}
	defaults := map[string]string{"DOMAIN": "example.com", "UPCLOUD_ZONE": "uk-lon1", "UPCLOUD_PLAN": "STARTER-1xCPU-1GB"}
	for k, v := range defaults {
		if env.Get(k) == "" {
			env.Set(k, v)
		}
	}
	if err := env.Save(); err != nil {
		fatalf("%v", err)
	}
	if _, err := os.Stat(sshKey); os.IsNotExist(err) {
		step("creating SSH key %s", sshKey)
		run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nomax-ops", "-f", sshKey)
	}
	step("ready: %s", envPath)
}

func tofuEnv(env *Env) []string {
	pub, err := os.ReadFile(sshKey + ".pub")
	if err != nil {
		fatalf("no SSH key; run make init")
	}
	return []string{
		"UPCLOUD_TOKEN=" + env.Must("UPCLOUD_TOKEN"),
		"CLOUDFLARE_API_TOKEN=" + env.Must("CLOUDFLARE_API_TOKEN"),
		"TF_VAR_domain=" + env.Must("DOMAIN"),
		"TF_VAR_zone=" + env.Must("UPCLOUD_ZONE"),
		"TF_VAR_plan=" + env.Must("UPCLOUD_PLAN"),
		"TF_VAR_cloudflare_zone_id=" + env.Must("CLOUDFLARE_ZONE_ID"),
		"TF_VAR_ssh_public_key=" + strings.TrimSpace(string(pub)),
		"TF_IN_AUTOMATION=1",
		"TF_WORKSPACE=" + tofuWorkspace(env),
	}
}

// tofuWorkspace keeps each server's OpenTofu state apart (TOFU_WORKSPACE),
// so a new domain can come up while the old one still runs.
func tofuWorkspace(env *Env) string {
	if ws := env.Get("TOFU_WORKSPACE"); ws != "" {
		return ws
	}
	return "default"
}

func tofuState(env *Env) string {
	if ws := tofuWorkspace(env); ws != "default" {
		return filepath.Join("infra", "terraform.tfstate.d", ws, "terraform.tfstate")
	}
	return "infra/terraform.tfstate"
}

func tofu(env *Env, args ...string) {
	if err := runErr(tofuEnv(env), "tofu", append([]string{"-chdir=infra"}, args...)...); err != nil {
		fatalf("tofu %s: %v", args[0], err)
	}
}

func tofuOutput(env *Env, name string) string {
	if _, err := os.Stat(tofuState(env)); err != nil {
		return ""
	}
	c := exec.Command("tofu", "-chdir=infra", "output", "-raw", name)
	c.Env = append(os.Environ(), tofuEnv(env)...)
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func cmdUp(env *Env, args []string) {
	if env.Get("WG_PRIVATE_KEY") == "" {
		cmdInit(env, nil)
	}
	if _, err := os.Stat("infra/.terraform"); os.IsNotExist(err) {
		tofu(env, "init", "-input=false")
	}
	if ws := tofuWorkspace(env); ws != "default" {
		if _, err := os.Stat(filepath.Join("infra", "terraform.tfstate.d", ws)); os.IsNotExist(err) {
			run("tofu", "-chdir=infra", "workspace", "new", ws)
		}
	}
	step("provisioning %s in %s", env.Must("DOMAIN"), env.Must("UPCLOUD_ZONE"))
	tofu(env, "apply", "-input=false", "-auto-approve")
	ip := tofuOutput(env, "ipv4")
	if ip == "" {
		fatalf("no IPv4 output")
	}
	if _, err := os.Stat(knownHosts); err == nil {
		exec.Command("ssh-keygen", "-q", "-R", ip, "-f", knownHosts).Run()
		exec.Command("ssh-keygen", "-q", "-R", env.Must("DOMAIN"), "-f", knownHosts).Run()
	}
	os.Setenv("SERVER_HOST", ip)
	waitSSH(ip)
	cmdDeploy(env, args)
	if exec.Command("gh", "secret", "list").Run() == nil {
		cmdGHSecrets(env, nil)
	}
	if env.Get("DIRECTORY_SIGN") != "" {
		cmdPublish(env, nil)
	}
}

// saveState is what the server keeps in /var/lib/nomax minus the downloads,
// with the database copied by SQLite's online backup so it's consistent while
// the server runs.
const saveState = `set -e; t=$(mktemp -d); trap 'rm -rf "$t"' EXIT; cd /var/lib/nomax
tar -cf - --exclude=./public --exclude='./nomax.db*' . | tar -xf - -C "$t"
python3 -c 'import sqlite3, sys; d = sqlite3.connect(sys.argv[2]); sqlite3.connect(sys.argv[1]).backup(d); d.close()' nomax.db "$t/nomax.db"
tar -czf - -C "$t" .`

func cmdDown(env *Env, _ []string) {
	host := serverHost(env)
	step("saving server state to %s", stateTgz)
	if err := sshCapture(host, saveState, stateTgz); err != nil {
		fmt.Fprintf(os.Stderr, "ops: state not saved (%v); continuing\n", err)
	}
	tofu(env, "destroy", "-input=false", "-auto-approve")
}

// cmdStateSave copies the server's people, devices and keys to _cert/state.tgz
// and leaves it running; the next server's first deploy restores them.
func cmdStateSave(env *Env, _ []string) {
	host := serverHost(env)
	step("copying the state of %s to %s", host, stateTgz)
	if err := sshCapture(host, saveState, stateTgz); err != nil {
		fatalf("%v", err)
	}
}

func serverHost(env *Env) string {
	if h := os.Getenv("SERVER_HOST"); h != "" {
		return h
	}
	if ip := tofuOutput(env, "ipv4"); ip != "" {
		return ip
	}
	return env.Must("DOMAIN")
}

func sshArgs(host string) []string {
	return []string{
		"-i", sshKey,
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"root@" + host,
	}
}

func ssh(host, script string, stdin io.Reader) error {
	c := exec.Command("ssh", append(sshArgs(host), script)...)
	c.Stdin, c.Stdout, c.Stderr = stdin, os.Stdout, os.Stderr
	return c.Run()
}

func sshCapture(host, script, dest string) error {
	f, err := os.OpenFile(dest+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	c := exec.Command("ssh", append(sshArgs(host), script)...)
	c.Stdout, c.Stderr = f, os.Stderr
	err = c.Run()
	f.Close()
	if err != nil {
		os.Remove(dest + ".tmp")
		return err
	}
	return os.Rename(dest+".tmp", dest)
}

func waitSSH(host string) {
	step("waiting for SSH on %s", host)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		c := exec.Command("ssh", append(sshArgs(host), "true")...)
		if c.Run() == nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
	fatalf("SSH to %s did not come up", host)
}

func cmdSSH(env *Env, args []string) {
	c := exec.Command("ssh", append(sshArgs(serverHost(env)), args...)...)
	c.Args = slicesDelete(c.Args, "-o", "BatchMode=yes")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Run()
}

func slicesDelete(args []string, flag, val string) []string {
	out := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) && args[i+1] == val {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// cmdDeploy cross-compiles nomax and runs infra/host/setup.sh on the server.
func cmdDeploy(env *Env, _ []string) {
	host := serverHost(env)
	dir, err := os.MkdirTemp("", "nomax-deploy")
	if err != nil {
		fatalf("%v", err)
	}
	defer os.RemoveAll(dir)

	version := strings.TrimSpace(gitDescribe())
	step("building nomax %s for linux/amd64", version)
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+version, "-o", filepath.Join(dir, "nomax"), "./cmd/server")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fatalf("build: %v", err)
	}
	files, _ := filepath.Glob("infra/host/*")
	for _, f := range files {
		copyFile(f, filepath.Join(dir, filepath.Base(f)))
	}
	ocConf := filepath.Join(dir, "ocserv.conf")
	conf, err := os.ReadFile(ocConf)
	if err != nil {
		fatalf("%v", err)
	}
	conf = fmt.Appendf(conf, "\n# Anything without the apps' secret gets a 404.\ncamouflage = true\ncamouflage_secret = %q\n", vpn.OCSecret(env.Must("WG_PRIVATE_KEY")))
	if err := os.WriteFile(ocConf, conf, 0o644); err != nil {
		fatalf("%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nomax.env"), []byte(env.serverEnv()), 0o600); err != nil {
		fatalf("%v", err)
	}
	if _, err := os.Stat(stateTgz); err == nil {
		copyFile(stateTgz, filepath.Join(dir, "state.tgz"))
	}
	if link := serverLinkConf(env); link != "" {
		if err := os.WriteFile(filepath.Join(dir, "wgr.conf"), []byte(link), 0o600); err != nil {
			fatalf("%v", err)
		}
	}

	step("uploading to %s", host)
	tar := exec.Command("tar", "-czf", "-", "-C", dir, ".")
	tar.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	payload, err := tar.Output()
	if err != nil {
		fatalf("tar: %v", err)
	}
	remote := `set -e; d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; tar -xzf - -C "$d"; bash "$d/setup.sh"`
	if err := ssh(host, remote, bytes.NewReader(payload)); err != nil {
		fatalf("setup: %v", err)
	}
	step("setting the admin code (if unset)")
	if err := ssh(host, "runuser -u nomax -- env STATE_DIRECTORY=/var/lib/nomax /usr/local/bin/nomax admin-code -if-unset", strings.NewReader(env.Must("ADMIN_CODE")+"\n")); err != nil {
		fatalf("admin code: %v", err)
	}
	waitHealthy(env.Must("DOMAIN"), host)
	if os.Getenv("CI") != "" {
		step("deployed: https://%s", env.Must("DOMAIN"))
		return
	}
	step("deployed: https://%s/%s", env.Must("DOMAIN"), env.Must("ADMIN_PATH"))
}

func copyFile(src, dst string) {
	b, err := os.ReadFile(src)
	if err != nil {
		fatalf("%v", err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		fatalf("%v", err)
	}
}

func gitDescribe() string {
	out, err := exec.Command("git", "describe", "--always", "--dirty", "--tags").Output()
	if err != nil {
		return "dev"
	}
	return string(out)
}

// waitHealthy waits until the public site answers over TLS (through Reality's fallback).
func waitHealthy(domain, host string) {
	step("waiting for https://%s", domain)
	client := httpClientTo(domain, host, false)
	deadline := time.Now().Add(3 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + domain + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		last = err
		time.Sleep(5 * time.Second)
	}
	fmt.Fprintf(os.Stderr, "ops: site not healthy yet (%v); the certificate may still be issuing — run make check\n", last)
}

// httpClientTo pins connections for domain to host (DNS may lag behind a fresh server).
func httpClientTo(domain, host string, insecure bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: insecure},
			DialContext: func(ctx contextT, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return d.DialContext(ctx, network, net.JoinHostPort(host, port))
			},
		},
	}
}

func cmdCheck(env *Env, _ []string) {
	host := serverHost(env)
	domain := env.Must("DOMAIN")
	step("services on %s", host)
	ssh(host, `systemctl is-active nomax wg-quick@wg0 nftables | paste -sd' '; ss -lntup | awk 'NR==1 || /:(80|443|51820|51821|8443) /' ; wg show wg0 | head -5; ip -br link show awg0; journalctl -u nomax -n 15 --no-pager -o cat`, nil)

	step("DNS")
	ips, err := net.LookupHost(domain)
	fmt.Printf("%s -> %v %v\n", domain, ips, errString(err))

	step("TLS through Reality fallback")
	resp, err := httpClientTo(domain, host, false).Get("https://" + domain + "/")
	if err != nil {
		fmt.Println("FAIL:", err)
	} else {
		resp.Body.Close()
		cert := resp.TLS.PeerCertificates[0]
		fmt.Printf("ok %d, cert %s by %s, expires %s\n", resp.StatusCode, cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))
	}
	resp, err = httpClientTo(domain, host, false).Get("https://" + domain + "/admin")
	if err == nil {
		resp.Body.Close()
		fmt.Printf("/admin -> %d (want 404)\n", resp.StatusCode)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func cmdAdminCode(env *Env, _ []string) {
	code := os.Getenv("ADMIN_CODE_NEW")
	if code == "" {
		code = newAdminCode()
	}
	host := serverHost(env)
	step("rotating the admin code on %s", host)
	if err := ssh(host, "runuser -u nomax -- env STATE_DIRECTORY=/var/lib/nomax /usr/local/bin/nomax admin-code", strings.NewReader(code+"\n")); err != nil {
		fatalf("%v", err)
	}
	env.Set("ADMIN_CODE", code)
	if err := env.Save(); err != nil {
		fatalf("saved on server but not locally: %v", err)
	}
	step("new admin code stored in %s (all sessions signed out, lockouts cleared)", envPath)
}

// cmdReports shows what the apps sent with their Send button (nomax reports):
// what's new since the last look, or with -all everything kept.
func cmdReports(env *Env, args []string) {
	script := "runuser -u nomax -- env STATE_DIRECTORY=/var/lib/nomax /usr/local/bin/nomax reports"
	for _, a := range args {
		script += " '" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	if err := ssh(serverHost(env), script, nil); err != nil {
		fatalf("%v", err)
	}
}

func cmdGHSecrets(env *Env, _ []string) {
	repo := strings.TrimSpace(output("gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"))
	set := func(name, value string) {
		c := exec.Command("gh", "secret", "set", name, "--repo", repo)
		c.Stdin = strings.NewReader(value)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			fatalf("gh secret set %s: %v", name, err)
		}
	}
	key, err := os.ReadFile(sshKey)
	if err != nil {
		fatalf("%v", err)
	}
	var env2 strings.Builder
	for _, l := range env.lines {
		if k, v, ok := parseLine(l); ok && v != "" && !strings.HasPrefix(k, "UPCLOUD") && !strings.HasPrefix(k, "CLOUDFLARE") {
			fmt.Fprintf(&env2, "%s=%s\n", k, env.Get(k))
		}
	}
	set("NOMAX_ENV", env2.String())
	set("SSH_KEY", string(key))
	if ip := tofuOutput(env, "ipv4"); ip != "" {
		run("gh", "variable", "set", "SERVER_HOST", "--repo", repo, "--body", ip)
	}
	if kh, err := os.ReadFile(knownHosts); err == nil {
		set("SSH_KNOWN_HOSTS", string(kh))
	}
	if p8 := env.Get("ASC_KEY_FILE"); p8 != "" {
		b, err := os.ReadFile(filepath.Join("_cert", p8))
		if err != nil {
			fatalf("%v", err)
		}
		set("ASC_KEY_P8", string(b))
	}
	if b, err := os.ReadFile(installerP12); err == nil {
		set("MAC_INSTALLER_P12_BASE64", encodeB64(b))
	}
	if b, err := os.ReadFile(androidKeystore); err == nil {
		set("ANDROID_KEYSTORE_BASE64", encodeB64(b))
	}
	if b, err := os.ReadFile(distP12); err == nil {
		set("DIST_P12_BASE64", encodeB64(b))
		if env.Get("ASC_APP_ID") != "" && env.Get("DIST_P12_PASSWORD") != "" {
			run("gh", "variable", "set", "TESTFLIGHT", "--repo", repo, "--body", "on")
		}
	}
	step("secrets set on %s", repo)
}
