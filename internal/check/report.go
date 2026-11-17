package check

import (
	"fmt"
	"strings"
	"time"
)

// verdict sums up a finished check in a sentence or three.
func verdict(rep Report) string {
	st := map[string]string{}
	for _, s := range rep.Steps {
		st[s.ID] = s.State
	}
	ok := func(id string) bool { return st[id] == OK }
	failed := func(id string) bool { return st[id] == Fail }

	if failed("apple") && failed("yandex") && failed("web") {
		return "This device doesn't seem to be online."
	}
	var parts []string
	if failed("dns") && (ok("dns.cloudflare") || ok("dns.google")) {
		parts = append(parts, "Your network's DNS gives a wrong address for "+rep.Host+".")
	}
	switch {
	case failed("tcp") && failed("upcloud"):
		parts = append(parts, "This network blocks our hosting provider, UpCloud, so it can't reach our server.")
	case failed("tcp"):
		parts = append(parts, "This network blocks our server's address.")
	case failed("tls") && ok("tls.other"):
		parts = append(parts, "This network blocks our server's name, "+rep.Host+", but not its address.")
	case failed("tls"):
		parts = append(parts, "This network lets connections reach our server but breaks them before they're secured.")
	case failed("download"):
		parts = append(parts, "This network cuts connections to our server after the first few kilobytes, a common way of blocking VPNs.")
	case failed("udp"):
		parts = append(parts, "Our server is reachable over TCP, but UDP to it is blocked: Hysteria2, WireGuard and AmneziaWG won't work, the others can.")
	default:
		parts = append(parts, "Our server is reachable from this network.")
	}
	direct := ok("tcp") && ok("tls") && ok("download")
	switch {
	case direct:
		parts = append(parts, "If the VPN still doesn't connect, send this report.")
	case failed("web"):
		parts = append(parts, "The route through Cloudflare is blocked too.")
	case ok("web.download"):
		parts = append(parts, "The route through Cloudflare works.")
	case ok("web"):
		parts = append(parts, "Through Cloudflare the website loads, but downloads stall.")
	}
	return strings.Join(parts, " ")
}

// Text is the report for sending: no keys or passwords, only addresses and
// what happened.
func (rep Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "NoMax connection check, %s UTC\n", time.UnixMilli(rep.Started).UTC().Format("2 Jan 2006 15:04"))
	if rep.App != "" {
		b.WriteString(rep.App + "\n")
	}
	fmt.Fprintf(&b, "Server: %s\n", rep.Host)
	switch {
	case rep.Verdict != "":
		fmt.Fprintf(&b, "\n%s\n", rep.Verdict)
	case !rep.Done:
		b.WriteString("\nStill running.\n")
	}
	group := ""
	for _, s := range rep.Steps {
		if s.Group != group {
			group = s.Group
			fmt.Fprintf(&b, "\n%s\n", group)
		}
		line := "  " + mark(s.State) + " " + s.Title
		if s.Detail != "" {
			line += ": " + s.Detail
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func mark(state string) string {
	switch state {
	case OK:
		return "✓"
	case Fail:
		return "✗"
	case Info:
		return "•"
	}
	return "…"
}
