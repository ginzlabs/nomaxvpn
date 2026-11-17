package profile

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// NewWireGuardKey returns a WireGuard private key in standard base64.
func NewWireGuardKey() string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

// WireGuardPublic derives the public key of a base64 WireGuard private key.
func WireGuardPublic(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ValidWireGuardKey reports whether s is a base64 32-byte key.
func ValidWireGuardKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// NewRealityKey returns a Reality (X25519) private key in Xray's raw URL base64.
func NewRealityKey() string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes())
}

// RealityPublic derives the client-side public key ("password") of a Reality private key.
func RealityPublic(private string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("reality key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// RandomHex returns n random bytes as hex.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// RandomToken returns n random bytes as raw URL base64.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
