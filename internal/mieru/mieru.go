// Package mieru runs Mieru (github.com/enfein/mieru, GPLv3): a stream cipher
// over plain TCP with no handshake to fingerprint, whose keys come from the
// password and the clock, and with random padding.
package mieru

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mc "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	ms "github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/ginzlabs/nomaxvpn/internal/bridge"
	"google.golang.org/protobuf/proto"
)

// kickAfter is how long a new stream waits for the app's first bytes before
// sending its request alone. Mieru sends the request with the first write, so
// a protocol where the server speaks first (SSH, SMTP) would otherwise hang.
const kickAfter = 200 * time.Millisecond

// Config is where a client connects and its login.
type Config struct {
	// Address is the server's IP and port.
	Address, Username, Password string
}

type Client struct{ c mc.Client }

var _ bridge.Dialer = (*Client)(nil)

func NewClient(cfg Config) (*Client, error) {
	host, portStr, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	c := mc.NewClient()
	if err := c.Store(&mc.ClientConfig{Profile: &pb.ClientProfile{
		ProfileName: proto.String("nomax"),
		User:        &pb.User{Name: proto.String(cfg.Username), Password: proto.String(cfg.Password)},
		Servers: []*pb.ServerEndpoint{{
			IpAddress:    proto.String(host),
			PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: pb.TransportProtocol_TCP.Enum()}},
		}},
		Multiplexing:  &pb.MultiplexingConfig{Level: pb.MultiplexingLevel_MULTIPLEXING_HIGH.Enum()},
		HandshakeMode: pb.HandshakeMode_HANDSHAKE_NO_WAIT.Enum(),
	}}); err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (c *Client) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dst := model.NetAddrSpec{Net: "tcp"}
	if err := dst.AddrSpec.From(addr); err != nil {
		return nil, err
	}
	conn, err := c.c.DialContext(ctx, dst)
	if err != nil {
		return nil, err
	}
	return kick(conn), nil
}

// DialUDP carries every datagram of the association over one stream, each
// with its destination in a SOCKS5 UDP header.
func (c *Client) DialUDP(ctx context.Context) (bridge.PacketConn, error) {
	conn, err := c.c.DialContext(ctx, &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	return &packets{pc: apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))}, nil
}

func (c *Client) Close() error { return c.c.Stop() }

type kicked struct {
	net.Conn
	wrote atomic.Bool
	timer *time.Timer
}

func kick(c net.Conn) *kicked {
	k := &kicked{Conn: c}
	k.timer = time.AfterFunc(kickAfter, func() {
		if !k.wrote.Swap(true) {
			c.Write(nil)
		}
	})
	return k
}

func (k *kicked) Write(b []byte) (int, error) {
	k.wrote.Store(true)
	return k.Conn.Write(b)
}

func (k *kicked) Close() error {
	k.timer.Stop()
	return k.Conn.Close()
}

type packets struct{ pc net.PacketConn }

func (p *packets) WriteTo(b []byte, to netip.AddrPort) error {
	_, err := p.pc.WriteTo(b, net.UDPAddrFromAddrPort(to))
	return err
}

func (p *packets) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, from, err := p.pc.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ua, _ := from.(*net.UDPAddr)
	if ua == nil {
		return 0, netip.AddrPort{}, errors.New("mieru: datagram from a name")
	}
	return n, ua.AddrPort(), nil
}

func (p *packets) Close() error { return p.pc.Close() }

// Server is Mieru on a TCP port. Mieru can't change its users while it runs,
// so SetUsers starts a new one; streams already open carry on.
type Server struct {
	// IP to listen on; empty means every address.
	IP      string
	Port    int
	DialTCP func(ctx context.Context, addr, email string) (net.Conn, error)
	DialUDP func(ctx context.Context, email string) (net.PacketConn, error)

	mu  sync.Mutex
	srv ms.Server
	key string
}

// SetUsers replaces the logins: the device's email (its Mieru username) to
// its password.
func (s *Server) SetUsers(passwords map[string]string) error {
	names := make([]string, 0, len(passwords))
	for name := range passwords {
		names = append(names, name)
	}
	sort.Strings(names)
	users := make([]*pb.User, 0, len(names))
	var key strings.Builder
	for _, name := range names {
		users = append(users, &pb.User{Name: proto.String(name), Password: proto.String(passwords[name])})
		key.WriteString(name + "\x00" + passwords[name] + "\x00")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil && s.key == key.String() {
		return nil
	}
	if s.srv != nil {
		s.srv.Stop()
		s.srv = nil
	}
	if len(users) == 0 {
		s.key = ""
		return nil
	}
	srv := ms.NewServer()
	if err := srv.Store(&ms.ServerConfig{Config: &pb.ServerConfig{
		ListenIPAddress: proto.String(s.IP),
		PortBindings:    []*pb.PortBinding{{Port: proto.Int32(int32(s.Port)), Protocol: pb.TransportProtocol_TCP.Enum()}},
		Users:           users,
	}}); err != nil {
		return err
	}
	var err error
	for range 10 {
		if err = srv.Start(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	s.srv, s.key = srv, key.String()
	// Accept reads each stream's request before it returns, so a few run at
	// once and one slow client doesn't hold up the rest.
	for range 8 {
		go s.serve(srv)
	}
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		s.srv.Stop()
		s.srv = nil
	}
	s.key = ""
	return nil
}

func (s *Server) serve(srv ms.Server) {
	for {
		c, req, err := srv.Accept()
		if err != nil {
			if !srv.IsRunning() {
				return
			}
			continue
		}
		go s.handle(c, req)
	}
}

func (s *Server) handle(c net.Conn, req *model.Request) {
	defer c.Close()
	var email string
	if u, ok := c.(apicommon.UserContext); ok {
		email = u.UserName()
	}
	switch req.Command {
	case constant.Socks5ConnectCmd:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		up, err := s.DialTCP(ctx, req.DstAddr.String(), email)
		cancel()
		if err != nil {
			reply(c, constant.Socks5ReplyHostUnreachable)
			return
		}
		defer up.Close()
		if reply(c, constant.Socks5ReplySuccess) == nil {
			bridge.Pipe(c, up)
		}
	case constant.Socks5UDPAssociateCmd:
		pc, err := s.DialUDP(context.Background(), email)
		if err != nil {
			reply(c, constant.Socks5ReplyServerFailure)
			return
		}
		defer pc.Close()
		if reply(c, constant.Socks5ReplySuccess) == nil {
			relay(apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(c)), pc)
		}
	default:
		reply(c, constant.Socks5ReplyCommandNotSupported)
	}
}

func reply(c net.Conn, code byte) error {
	r := &model.Response{Reply: code, BindAddr: model.AddrSpec{IP: net.IPv4zero}}
	return r.WriteToSocks5(c)
}

// relay moves datagrams between the client's stream and the server's socket
// until either side closes.
func relay(stream, out net.PacketConn) {
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := out.ReadFrom(buf)
			if err != nil {
				stream.Close()
				return
			}
			if _, err := stream.WriteTo(buf[:n], from); err != nil {
				out.Close()
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, to, err := stream.ReadFrom(buf)
		if err != nil {
			out.Close()
			return
		}
		out.WriteTo(buf[:n], to)
	}
}
