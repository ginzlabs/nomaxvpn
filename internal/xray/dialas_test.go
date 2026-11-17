package xray

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TrustTunnel and Mieru bound the dial with a timeout they cancel once it
// returns; the connection must outlive that.
func TestDialAsOutlivesContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	inst, err := Start([]byte(`{"outbounds": [{"protocol": "freedom"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c, err := inst.DialAs(ctx, ln.Addr().String(), "test", "d1")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(100 * time.Millisecond)

	got := make(chan string, 1)
	go func() {
		b := make([]byte, 4)
		if _, err := c.Write([]byte("ping")); err != nil {
			got <- "write: " + err.Error()
			return
		}
		if _, err := io.ReadFull(c, b); err != nil {
			got <- "read: " + err.Error()
			return
		}
		got <- string(b)
	}()
	select {
	case s := <-got:
		if s != "ping" {
			t.Fatalf("echo %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no echo: the connection died with its dial context")
	}
}
