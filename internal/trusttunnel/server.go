package trusttunnel

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// udpIdle ends a datagram flow nothing has crossed for this long (the spec's 120 s).
const udpIdle = 2 * time.Minute

// Server is TrustTunnel in front of a website. HTTP/2 CONNECT with a device's
// login is tunnelled; everything else, a wrong login included, gets the site,
// so a probe sees an ordinary web server.
type Server struct {
	// Auth checks a login and names the device for traffic accounting.
	Auth func(username, password string) (email string, ok bool)
	// DialTCP and DialUDP reach the internet for a device.
	DialTCP func(ctx context.Context, addr, email string) (net.Conn, error)
	DialUDP func(ctx context.Context, email string) (net.PacketConn, error)
	Site    http.Handler
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.ProtoMajor != 2 {
		s.Site.ServeHTTP(w, r)
		return
	}
	email, ok := s.login(r)
	if !ok {
		s.Site.ServeHTTP(w, r)
		return
	}
	switch r.Host {
	case checkHost:
		w.WriteHeader(http.StatusOK)
	case udpHost:
		s.serveUDP(w, r, email)
	case icmpHost:
		w.WriteHeader(http.StatusNotImplemented)
	default:
		s.serveTCP(w, r, email)
	}
}

func (s *Server) login(r *http.Request) (string, bool) {
	v, ok := strings.CutPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
	if !ok {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", false
	}
	user, pass, ok := strings.Cut(string(b), ":")
	if !ok {
		return "", false
	}
	return s.Auth(user, pass)
}

func (s *Server) serveTCP(w http.ResponseWriter, r *http.Request, email string) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port == "0" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	up, err := s.DialTCP(ctx, net.JoinHostPort(host, port), email)
	cancel()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer up.Close()
	stop := context.AfterFunc(r.Context(), func() { up.Close() })
	defer stop()
	w.WriteHeader(http.StatusOK)
	fw := flusher(w)
	fw.Flush()
	go func() {
		if _, err := io.Copy(up, r.Body); err != nil {
			up.Close()
		}
	}()
	io.Copy(fw, up)
}

func (s *Server) serveUDP(w http.ResponseWriter, r *http.Request, email string) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	w.WriteHeader(http.StatusOK)
	fw := flusher(w)
	fw.Flush()
	type flow struct {
		pc   net.PacketConn
		last time.Time
	}
	var (
		mu    sync.Mutex
		wmu   sync.Mutex
		flows = map[netip.AddrPort]*flow{}
	)
	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.pc.Close()
		}
		mu.Unlock()
	}()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				for k, f := range flows {
					if time.Since(f.last) > udpIdle {
						f.pc.Close()
						delete(flows, k)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, maxFrame)
	for {
		d, err := readFrame(r.Body, buf, true)
		if err != nil {
			return
		}
		if !d.dst.IsValid() || d.dst.Port() == 0 {
			continue
		}
		mu.Lock()
		f := flows[d.src]
		if f == nil {
			pc, err := s.DialUDP(ctx, email)
			if err != nil {
				mu.Unlock()
				continue
			}
			f = &flow{pc: pc}
			flows[d.src] = f
			go func(src netip.AddrPort, pc net.PacketConn) {
				rb := make([]byte, 65535)
				var out []byte
				for {
					n, from, err := pc.ReadFrom(rb)
					if err != nil {
						return
					}
					ua, ok := from.(*net.UDPAddr)
					if !ok {
						continue
					}
					mu.Lock()
					if f := flows[src]; f != nil {
						f.last = time.Now()
					}
					mu.Unlock()
					out = appendFrame(out[:0], datagram{src: ua.AddrPort(), dst: src, payload: rb[:n]}, false)
					wmu.Lock()
					_, err = fw.Write(out)
					if err == nil {
						fw.Flush()
					}
					wmu.Unlock()
					if err != nil {
						cancel()
						return
					}
				}
			}(d.src, pc)
		}
		f.last = time.Now()
		pc := f.pc
		mu.Unlock()
		pc.WriteTo(d.payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.dst.Addr().Unmap(), d.dst.Port())))
	}
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func flusher(w http.ResponseWriter) flushWriter {
	f, _ := w.(http.Flusher)
	return flushWriter{w, f}
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err == nil && f.f != nil {
		f.f.Flush()
	}
	return n, err
}

func (f flushWriter) Flush() {
	if f.f != nil {
		f.f.Flush()
	}
}
