package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRouteSNI(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	got := make(chan string, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		sig := make([]byte, 12)
		io.ReadFull(c, sig)
		got <- string(sig)
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := routeSNI(front, "vpn.example", backend.Addr().String(), slog.New(slog.DiscardHandler))
	defer ln.Close()

	dial := func(name string, protos ...string) {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			tc := tls.Client(c, &tls.Config{ServerName: name, NextProtos: protos, InsecureSkipVerify: true})
			tc.SetDeadline(time.Now().Add(2 * time.Second))
			tc.Handshake()
			c.Close()
		}()
	}

	dial("vpn.example")
	select {
	case sig := <-got:
		if sig != "\r\n\r\n\x00\r\nQUIT\n" {
			t.Fatalf("backend got %q, want a PROXY v2 header", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vpn.example did not reach the backend")
	}

	for _, c := range []struct {
		name   string
		protos []string
	}{{"example", nil}, {"vpn.example", []string{"acme-tls/1"}}} {
		dial(c.name, c.protos...)
		accepted := make(chan net.Conn, 1)
		go func() {
			if a, err := ln.Accept(); err == nil {
				accepted <- a
			}
		}()
		select {
		case a := <-accepted:
			line, _ := bufio.NewReader(a).Peek(1)
			if len(line) != 1 || line[0] != 0x16 {
				t.Errorf("%s %v: Accept got %q, want the replayed ClientHello", c.name, c.protos, line)
			}
			a.Close()
		case <-time.After(5 * time.Second):
			t.Fatalf("%s %v was not handed to Accept", c.name, strings.Join(c.protos, ","))
		}
	}
}
