package nomaxcore

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Auto learns its order from what it tries: protocols that got through go
// first, the latest first, and those that failed go last, the latest last,
// with the ones not tried yet between. On a network that blocks some
// protocols on sight, as some do WireGuard and OpenVPN, Auto soon stops
// trying them first. Apps keep the order (Preferred) and pass it back to
// Start; the process keeps it too, which on Windows and Android outlives runs.
var (
	learnMu sync.Mutex
	learned order
)

// order is Preferred's "worked,worked|failed,failed". A plain protocol, what
// apps kept before, is one that worked.
type order struct{ good, bad []string }

func parseOrder(s string) order {
	good, bad, _ := strings.Cut(s, "|")
	return order{protocolList(good), protocolList(bad)}
}

func protocolList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func (o order) String() string {
	if len(o.good) == 0 && len(o.bad) == 0 {
		return ""
	}
	return strings.Join(o.good, ",") + "|" + strings.Join(o.bad, ",")
}

func (o *order) drop(p string) {
	o.good = slices.DeleteFunc(o.good, func(q string) bool { return q == p })
	o.bad = slices.DeleteFunc(o.bad, func(q string) bool { return q == p })
}

func (o *order) worked(p string) {
	o.drop(p)
	o.good = append([]string{p}, o.good...)
}

func (o *order) failed(p string) {
	o.drop(p)
	o.bad = append(o.bad, p)
}

// Preferred is the order Auto has learned, for the app to keep and pass to
// the next Start.
func Preferred() string {
	learnMu.Lock()
	defer learnMu.Unlock()
	return learned.String()
}

// learnFrom takes the app's kept order unless this process has learned one.
func learnFrom(preferred string) {
	learnMu.Lock()
	defer learnMu.Unlock()
	if learned.String() == "" {
		learned = parseOrder(preferred)
	}
}

func learnWorked(p string) {
	learnMu.Lock()
	defer learnMu.Unlock()
	learned.worked(p)
}

func learnFailed(p string) {
	learnMu.Lock()
	defer learnMu.Unlock()
	learned.failed(p)
}

// learnQuickest puts what worked in a Test run first, the quickest first.
func learnQuickest(took map[string]time.Duration) {
	protos := make([]string, 0, len(took))
	for p := range took {
		protos = append(protos, p)
	}
	slices.SortFunc(protos, func(a, b string) int { return cmp.Compare(took[b], took[a]) })
	learnMu.Lock()
	defer learnMu.Unlock()
	for _, p := range protos {
		learned.worked(p)
	}
}

// autoOrder is the protocols the profile offers in the order preferred
// gives: those that worked, those not tried, in profile.Protocols' order,
// then those that failed.
func autoOrder(p profile.Profile, preferred string) []string {
	o := parseOrder(preferred)
	var out []string
	add := func(proto string) {
		if slices.Contains(profile.Protocols, proto) && profile.Offered(p, proto) && !slices.Contains(out, proto) {
			out = append(out, proto)
		}
	}
	for _, proto := range o.good {
		add(proto)
	}
	for _, proto := range profile.Protocols {
		if !slices.Contains(o.bad, proto) {
			add(proto)
		}
	}
	for _, proto := range o.bad {
		add(proto)
	}
	return out
}

// lastTitles names the protocols of order that preferred has as failed, for the log.
func lastTitles(order []string, preferred string) []string {
	bad := parseOrder(preferred).bad
	var out []string
	for _, proto := range order {
		if slices.Contains(bad, proto) {
			out = append(out, profile.Title(proto))
		}
	}
	return out
}
