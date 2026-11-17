package vpn

import (
	"crypto/sha512"
	"strings"
)

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sha512Crypt is crypt(3)'s "$6$" scheme with the default 5000 rounds, the
// format ocserv's plain password file takes. salt is at most 16 characters
// from cryptAlphabet.
func sha512Crypt(password, salt string) string {
	const rounds = 5000
	p, s := []byte(password), []byte(salt)
	h := sha512.New()
	h.Write(p)
	h.Write(s)
	h.Write(p)
	b := h.Sum(nil)

	h.Reset()
	h.Write(p)
	h.Write(s)
	for i := len(p); i > 0; i -= 64 {
		h.Write(b[:min(i, 64)])
	}
	for i := len(p); i > 0; i >>= 1 {
		if i&1 != 0 {
			h.Write(b)
		} else {
			h.Write(p)
		}
	}
	a := h.Sum(nil)

	h.Reset()
	for range p {
		h.Write(p)
	}
	dp := h.Sum(nil)
	pseq := make([]byte, 0, len(p))
	for i := len(p); i > 0; i -= 64 {
		pseq = append(pseq, dp[:min(i, 64)]...)
	}

	h.Reset()
	for range 16 + int(a[0]) {
		h.Write(s)
	}
	sseq := h.Sum(nil)[:len(s)]

	c := a
	for i := range rounds {
		h.Reset()
		if i&1 != 0 {
			h.Write(pseq)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(sseq)
		}
		if i%7 != 0 {
			h.Write(pseq)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(pseq)
		}
		c = h.Sum(nil)
	}

	var out strings.Builder
	out.WriteString("$6$" + salt + "$")
	enc := func(b2, b1, b0 byte, n int) {
		w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for range n {
			out.WriteByte(cryptAlphabet[w&0x3f])
			w >>= 6
		}
	}
	for i := range 21 {
		x, y, z := c[i], c[i+21], c[i+42]
		switch i % 3 {
		case 1:
			x, y, z = y, z, x
		case 2:
			x, y, z = z, x, y
		}
		enc(x, y, z, 4)
	}
	enc(0, 0, c[63], 2)
	return out.String()
}
