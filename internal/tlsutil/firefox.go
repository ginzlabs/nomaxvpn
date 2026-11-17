package tlsutil

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// dialTimeout bounds the connection and its handshake. A blocked server
// otherwise holds a dial for the system's two minutes, and TrustTunnel's client
// dials under a lock its other connections wait on.
const dialTimeout = 15 * time.Second

// Firefox dials addr and does TLS with Firefox's ClientHello, verifying
// serverName against roots (nil means the system's). Reality uses the same
// fingerprint (profile.Fingerprint).
func Firefox(ctx context.Context, addr, serverName string, roots *x509.CertPool) (*utls.UConn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(dialTimeout))
	uc := utls.UClient(raw, &utls.Config{ServerName: serverName, RootCAs: roots}, utls.HelloFirefox_Auto)
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS: %w", err)
	}
	raw.SetDeadline(time.Time{})
	return uc, nil
}
