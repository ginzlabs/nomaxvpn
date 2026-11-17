package vpn

import (
	"strings"
	"testing"
)

func TestSHA512Crypt(t *testing.T) {
	for _, c := range []struct{ pass, salt, want string }{
		// From the SHA-crypt specification.
		{"Hello world!", "saltstring", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		// From openssl passwd -6.
		{"trialpass123", "abcdefgh", "$6$abcdefgh$06gR9SqBCzD2QXV4bprIA.dQdZdLIA6FI3lraf8vicEp4tA5Z5vd1hMGSMjHcxN6NN8QRrXf3na4KhHS/9wrn0"},
		{strings.Repeat("a", 130), "0123456789abcdef", "$6$0123456789abcdef$PvZSErPxbFxIdUSd.emfqBu/mGaZ1yVkHQQIDuFhmzMmidmQwbYk0phO7ZpXH.0FWVU8v10YWteCaqz4js9Yl."},
	} {
		if got := sha512Crypt(c.pass, c.salt); got != c.want {
			t.Errorf("sha512Crypt(%q, %q)\n got %s\nwant %s", c.pass, c.salt, got, c.want)
		}
	}
}
