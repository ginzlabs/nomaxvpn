package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Relays forward every protocol's port to the server from another country's
// address, for networks that block the server's own. RELAYS in
// _cert/nomax.env lists their IPv4 addresses; the first also carries the
// exit route over the WireGuard link (wgr, 10.9.0.0/24, UDP 51830).
func relays(env *Env) []string {
	var out []string
	for r := range strings.SplitSeq(env.Get("RELAYS"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// linkKey is a WireGuard key for one end of the relay link ("server", or a
// relay's address), derived from the server's key so it needs no storage.
func linkKey(env *Env, end string) string {
	sum := sha256.Sum256([]byte("nomax relay link\x00" + end + "\x00" + env.Must("WG_PRIVATE_KEY")))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func linkPublic(env *Env, end string) string {
	pub, err := profile.WireGuardPublic(linkKey(env, end))
	if err != nil {
		fatalf("link key: %v", err)
	}
	return pub
}

func linkAddr(i int) string { return fmt.Sprintf("10.9.0.%d", i+2) }

// serverLinkConf is the server's wgr.conf, "" without relays. Xray's
// exit outbound sends from 10.9.0.1, and table 51830 sends that out
// through the link, where the first relay's peer takes everything.
func serverLinkConf(env *Env) string {
	rs := relays(env)
	if len(rs) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, `[Interface]
Address = 10.9.0.1/24
ListenPort = 51830
PrivateKey = %s
Table = off
PostUp = ip rule add from 10.9.0.1 lookup 51830 priority 1000; ip route replace default dev wgr table 51830; ip route replace 10.9.0.0/24 dev wgr table 51830
PostDown = ip rule del from 10.9.0.1 lookup 51830 priority 1000 || true
`, linkKey(env, "server"))
	for i, ip := range rs {
		allowed := linkAddr(i) + "/32"
		if i == 0 {
			allowed += ", 0.0.0.0/0"
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s:51830\nPersistentKeepalive = 25\n", linkPublic(env, ip), allowed, ip)
	}
	return b.String()
}

// serverIPv4 is the server's public IPv4 address, which relays forward to.
func serverIPv4(env *Env) string {
	if ip := tofuOutput(env, "ipv4"); ip != "" {
		return ip
	}
	ips, err := net.LookupIP(env.Must("DOMAIN"))
	if err != nil {
		fatalf("server address: %v", err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	fatalf("%s has no IPv4 address", env.Must("DOMAIN"))
	return ""
}

// cmdRelay sets up the relay at RELAY (or every relay in RELAYS), adds it to
// RELAYS, and redeploys the server so its end of the link and the apps'
// profiles include it. A new machine's root password, if it has no key of
// ours yet, comes from RELAY_PASSWORD. RELAY_VIA=link sends the forwarded
// traffic through the link instead of straight to the server's address.
// RELAY_TEMP=1 tries a relay without keeping it: nothing is saved, and the
// next deploy drops it.
func cmdRelay(env *Env, args []string) {
	temp := os.Getenv("RELAY_TEMP") != ""
	targets := relays(env)
	if r := os.Getenv("RELAY"); r != "" {
		targets = []string{r}
	}
	if len(targets) == 0 {
		fatalf("usage: RELAY=ip make relay")
	}
	server4 := serverIPv4(env)
	added := false
	for _, ip := range targets {
		if net.ParseIP(ip).To4() == nil {
			fatalf("%s is not an IPv4 address", ip)
		}
		list := relays(env)
		if !slices.Contains(list, ip) {
			env.Set("RELAYS", strings.Join(append(list, ip), ","))
			added = true
		}
		setupRelay(env, ip, slices.Index(relays(env), ip), server4)
	}
	if added && !temp {
		if err := env.Save(); err != nil {
			fatalf("%v", err)
		}
		step("RELAYS is now %s", env.Get("RELAYS"))
	}
	cmdDeploy(env, nil)
	if added && !temp && exec.Command("gh", "secret", "list").Run() == nil {
		cmdGHSecrets(env, nil)
	}
	if added && !temp && env.Get("DIRECTORY_SIGN") != "" {
		cmdPublish(env, nil)
	}
}

func setupRelay(env *Env, ip string, i int, server4 string) {
	step("relay %s (link %s)", ip, linkAddr(i))
	ensureRelayKey(ip)
	dir, err := os.MkdirTemp("", "nomax-relay")
	if err != nil {
		fatalf("%v", err)
	}
	defer os.RemoveAll(dir)
	files, _ := filepath.Glob("infra/relay/*")
	for _, f := range append(files, "infra/host/sshd.conf", "infra/host/unattended.conf", "infra/host/journald.conf") {
		copyFile(f, filepath.Join(dir, filepath.Base(f)))
	}
	via := "public"
	if os.Getenv("RELAY_VIA") == "link" {
		via = "link"
	}
	relayEnv := fmt.Sprintf("SERVER4=%s\nLINK_ADDR=%s\nLINK_KEY=%s\nSERVER_LINK_PUB=%s\nVIA=%s\n",
		server4, linkAddr(i), linkKey(env, ip), linkPublic(env, "server"), via)
	if err := os.WriteFile(filepath.Join(dir, "relay.env"), []byte(relayEnv), 0o600); err != nil {
		fatalf("%v", err)
	}
	tar := exec.Command("tar", "-czf", "-", "-C", dir, ".")
	tar.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	payload, err := tar.Output()
	if err != nil {
		fatalf("tar: %v", err)
	}
	remote := `set -e; d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; tar -xzf - -C "$d"; bash "$d/setup.sh"`
	if err := ssh(ip, remote, bytes.NewReader(payload)); err != nil {
		fatalf("relay setup: %v", err)
	}
}

// ensureRelayKey installs our SSH key on a new relay with its root password.
func ensureRelayKey(ip string) {
	if exec.Command("ssh", append(sshArgs(ip), "true")...).Run() == nil {
		return
	}
	pass := os.Getenv("RELAY_PASSWORD")
	if pass == "" {
		fatalf("can't log in to %s with our key; set RELAY_PASSWORD to its root password once", ip)
	}
	pub, err := os.ReadFile(sshKey + ".pub")
	if err != nil {
		fatalf("%v", err)
	}
	askpass, err := os.CreateTemp("", "askpass")
	if err != nil {
		fatalf("%v", err)
	}
	defer os.Remove(askpass.Name())
	askpass.WriteString("#!/bin/sh\nprintf '%s\\n' \"$RELAY_PASSWORD\"\n")
	askpass.Close()
	os.Chmod(askpass.Name(), 0o700)
	step("installing our SSH key on %s", ip)
	args := slicesDelete(sshArgs(ip), "-o", "BatchMode=yes")
	args = append([]string{"-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"}, args...)
	c := exec.Command("ssh", append(args, "umask 077; mkdir -p ~/.ssh; cat >>~/.ssh/authorized_keys")...)
	c.Env = append(os.Environ(), "SSH_ASKPASS="+askpass.Name(), "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none")
	c.Stdin, c.Stdout, c.Stderr = bytes.NewReader(pub), os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		fatalf("installing the key on %s: %v", ip, err)
	}
	if exec.Command("ssh", append(sshArgs(ip), "true")...).Run() != nil {
		fatalf("our key still doesn't log in to %s", ip)
	}
}
