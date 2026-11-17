package mieru_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/bridge/bridgetest"
	"github.com/ginzlabs/nomaxvpn/internal/mieru"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

func TestLoopback(t *testing.T) {
	must := bridgetest.Must
	var d net.Dialer
	emails := make(chan string, 64)
	srv := &mieru.Server{
		IP:   "127.0.0.1",
		Port: bridgetest.FreeTCP(t),
		DialTCP: func(ctx context.Context, addr, email string) (net.Conn, error) {
			select {
			case emails <- email:
			default:
			}
			return d.DialContext(ctx, "tcp", addr)
		},
		DialUDP: func(ctx context.Context, email string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
	}
	must(t, srv.SetUsers(map[string]string{"d1": "right-password"}))
	t.Cleanup(func() { srv.Close() })
	addr := net.JoinHostPort(srv.IP, strconv.Itoa(srv.Port))

	t.Run("wrong-password-no-tunnel", func(t *testing.T) {
		c, err := mieru.NewClient(mieru.Config{Address: addr, Username: "d1", Password: "wrong"})
		must(t, err)
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := c.DialTCP(ctx, bridgetest.Target(t))
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			b, _ := io.ReadAll(conn)
			conn.Close()
			if strings.Contains(string(b), bridgetest.Hello) {
				t.Fatal("a wrong password reached the target")
			}
		}
	})

	c, err := mieru.NewClient(mieru.Config{Address: addr, Username: "d1", Password: "right-password"})
	must(t, err)

	t.Run("server-speaks-first", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(t, err)
		defer ln.Close()
		go func() {
			s, err := ln.Accept()
			if err == nil {
				io.WriteString(s, "SSH-2.0-test\r\n")
				time.Sleep(time.Second)
				s.Close()
			}
		}()
		conn, err := c.DialTCP(context.Background(), ln.Addr().String())
		must(t, err)
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		must(t, err)
		if !strings.HasPrefix(string(buf[:n]), "SSH-2.0") {
			t.Fatalf("got %q", buf[:n])
		}
		if got := <-emails; got != "d1" {
			t.Fatalf("dialed as %q", got)
		}
	})

	t.Run("new-users-restart", func(t *testing.T) {
		must(t, srv.SetUsers(map[string]string{"d1": "right-password", "d2": "other"}))
	})

	bridgetest.Run(t, profile.Mieru, c)
}
