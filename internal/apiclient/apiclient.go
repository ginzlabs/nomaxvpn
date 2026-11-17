// Package apiclient reaches the device API by whichever way gets through:
// the server's own address, a relay (which forwards port 443 to the server,
// so TLS still names the server and its certificate still checks out), or
// the website's name behind Cloudflare. The apps join and refresh their
// profile through it, so a network that blocks the server still lets them.
package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/directory"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// Relays are the relays the apps were built with (-X
// github.com/ginzlabs/nomaxvpn/internal/apiclient.Relays=…, from RELAYS), for
// joining before a profile lists them. Comma-separated IPv4 addresses.
var Relays string

// Response is the server's answer.
type Response struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// Client is the device API at https://Host plus profile.API().
type Client struct {
	Host string
	// Relays are the relays' addresses; empty means the ones built in.
	Relays []string
	// RelayFirst tries the relays before the server's own address.
	RelayFirst bool
	// Roots verifies the server's certificate; nil is the system's (tests).
	Roots *x509.CertPool
	// Port is the HTTPS port; 0 is 443 (tests).
	Port string
	// Cloudflare is the website's name behind Cloudflare; "" is web.Host.
	Cloudflare string
}

// stagger is how long each way gets before the next one starts as well, and
// dialWait how long one may take to complete its handshake.
var (
	stagger  = 1500 * time.Millisecond
	dialWait = 10 * time.Second
)

func (c Client) port() string {
	if c.Port != "" {
		return c.Port
	}
	return "443"
}

func (c Client) relays() []string {
	if len(c.Relays) > 0 {
		return c.Relays
	}
	var out []string
	for r := range strings.SplitSeq(Relays, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// targets are where to open TLS to the server, in order.
func (c Client) targets() []string {
	own := []string{net.JoinHostPort(c.Host, c.port())}
	var relayed []string
	for _, r := range c.relays() {
		relayed = append(relayed, net.JoinHostPort(r, c.port()))
	}
	if c.RelayFirst {
		return append(relayed, own...)
	}
	return append(own, relayed...)
}

// dialTLS opens TLS to the server through the first target that completes a
// handshake. Each starts stagger after the one before, so a silent one costs
// little; the request then goes once, on the winner.
func (c Client) dialTLS(ctx context.Context) (net.Conn, error) {
	targets := c.targets()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(targets))
	for i, addr := range targets {
		go func() {
			t := time.NewTimer(time.Duration(i) * stagger)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			}
			d := tls.Dialer{
				NetDialer: &net.Dialer{Timeout: dialWait},
				Config:    &tls.Config{ServerName: c.Host, RootCAs: c.Roots, NextProtos: []string{"http/1.1"}},
			}
			conn, err := d.DialContext(ctx, "tcp", addr)
			results <- result{conn, err}
		}()
	}
	var errs []error
	for range targets {
		r := <-results
		if r.err == nil {
			cancel()
			go func(left int) {
				for ; left > 0; left-- {
					if r := <-results; r.conn != nil {
						r.conn.Close()
					}
				}
			}(len(targets) - 1 - len(errs))
			return r.conn, nil
		}
		errs = append(errs, r.err)
	}
	return nil, errors.Join(errs...)
}

// Do sends one request: through the server's address or a relay, else
// through Cloudflare, else the way the directory says, should the server
// have moved. err means no way reached the server.
func (c Client) Do(ctx context.Context, method, path, token string, body []byte) (Response, error) {
	resp, err := c.do(ctx, method, path, token, body)
	if err == nil || ctx.Err() != nil {
		return resp, err
	}
	e, derr := directory.Lookup(ctx)
	if derr != nil {
		return resp, err
	}
	// The server's own addresses are dialled like relays, for when its name is blocked.
	moved := c
	moved.Host, moved.Cloudflare = e.Host, ""
	moved.Relays = append(slices.Clone(e.IPs), e.Relays...)
	if len(e.Relays) == 0 {
		moved.Relays = append(moved.Relays, c.relays()...)
	}
	if r, merr := moved.do(ctx, method, path, token, body); merr == nil {
		return r, nil
	}
	return resp, err
}

func (c Client) do(ctx context.Context, method, path, token string, body []byte) (Response, error) {
	direct := &http.Client{Transport: &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return c.dialTLS(ctx)
		},
	}}
	resp, err := c.send(ctx, direct, c.Host, method, path, token, body)
	if err == nil || ctx.Err() != nil {
		return resp, err
	}
	web := c.Cloudflare
	if web == "" && net.ParseIP(c.Host) == nil {
		web = "web." + c.Host
	}
	if web == "" {
		return resp, err
	}
	cf := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: c.Roots}}}
	cfCtx, cancel := context.WithTimeout(ctx, dialWait)
	defer cancel()
	if r, cerr := c.send(cfCtx, cf, web, method, path, token, body); cerr == nil {
		return r, nil
	}
	return resp, err
}

func (c Client) send(ctx context.Context, hc *http.Client, host, method, path, token string, body []byte) (Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	url := "https://" + net.JoinHostPort(host, c.port()) + profile.API() + "/" + strings.TrimPrefix(path, "/")
	if c.port() == "443" {
		url = "https://" + host + profile.API() + "/" + strings.TrimPrefix(path, "/")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: resp.StatusCode, Body: string(b)}, nil
}

// Call is Do for the apps through gomobile: relays is comma-separated (""
// is the ones built in), route "relay" tries them first, and the answer is
// Response as JSON.
func Call(host, method, path, token, body, route, relays string) (string, error) {
	c := Client{Host: host, RelayFirst: route == "relay"}
	for r := range strings.SplitSeq(relays, ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.Relays = append(c.Relays, r)
		}
	}
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	resp, err := c.Do(ctx, method, path, token, b)
	if err != nil {
		first, _, _ := strings.Cut(err.Error(), "\n")
		return "", fmt.Errorf("Can't reach %s: %s", host, first)
	}
	out, _ := json.Marshal(resp)
	return string(out), nil
}
