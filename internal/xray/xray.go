// Package xray runs an in-process Xray-core instance from a JSON config.
package xray

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

type Instance struct{ core *core.Instance }

func Start(config []byte) (*Instance, error) {
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(config))
	if err != nil {
		return nil, fmt.Errorf("xray config: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("xray new: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("xray start: %w", err)
	}
	return &Instance{core: inst}, nil
}

func (i *Instance) Close() error {
	if i == nil {
		return nil
	}
	return i.core.Close()
}

// Dial opens a TCP connection through the instance's routing, as if from an inbound.
func (i *Instance) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dest, err := xnet.ParseDestination("tcp:" + addr)
	if err != nil {
		return nil, err
	}
	return core.Dial(ctx, i.core, dest)
}

// DialAs is Dial on behalf of a device that came in through a server outside
// Xray (TrustTunnel, AnyTLS, Mieru): the server's routing and final rules
// apply, and traffic counts under email like any inbound's. The connection
// lasts until it's closed, whatever happens to ctx.
func (i *Instance) DialAs(ctx context.Context, addr, tag, email string) (net.Conn, error) {
	dest, err := xnet.ParseDestination("tcp:" + addr)
	if err != nil {
		return nil, err
	}
	return core.Dial(asDevice(ctx, tag, email), i.core, dest)
}

// DialUDPAs is DialAs for datagrams: one socket that can send anywhere.
func (i *Instance) DialUDPAs(ctx context.Context, tag, email string) (net.PacketConn, error) {
	return core.DialUDP(asDevice(ctx, tag, email), i.core)
}

// asDevice drops ctx's cancellation: Xray ends a link when its context ends,
// and callers bound only the dial with theirs.
func asDevice(ctx context.Context, tag, email string) context.Context {
	return session.ContextWithInbound(context.WithoutCancel(ctx), &session.Inbound{Tag: tag, Name: tag, User: &protocol.MemoryUser{Email: email}})
}

// Counter reads a stats counter without resetting it (0 if absent).
func (i *Instance) Counter(name string) int64 {
	m, ok := i.core.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return 0
	}
	if c := m.GetCounter(name); c != nil {
		return c.Value()
	}
	return 0
}

// Traffic is bytes moved per user email since the last call (counters reset on read).
type Traffic struct{ Up, Down int64 }

func (i *Instance) TakeTraffic() map[string]Traffic {
	out := map[string]Traffic{}
	m, ok := i.core.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return out
	}
	type visitor interface {
		VisitCounters(func(string, stats.Counter) bool)
	}
	v, ok := m.(visitor)
	if !ok {
		return out
	}
	v.VisitCounters(func(name string, c stats.Counter) bool {
		// user>>>EMAIL>>>traffic>>>uplink|downlink
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			return true
		}
		n := c.Set(0)
		t := out[parts[1]]
		if parts[3] == "uplink" {
			t.Up += n
		} else {
			t.Down += n
		}
		out[parts[1]] = t
		return true
	})
	return out
}
