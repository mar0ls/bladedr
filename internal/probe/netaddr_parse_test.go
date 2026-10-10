package probe

import (
	"encoding/binary"
	"testing"
)

func TestParseHexAddr(t *testing.T) {
	// Fixtures are /proc/net/tcp{,6} lines as a little-endian kernel prints them.
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("fixtures are little-endian /proc/net output")
	}
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:0D05", "127.0.0.1", 3333}, // was reported as 1.0.0.127
		{"0500A8C0:0016", "192.168.0.5", 22},
		{"00000000:0050", "0.0.0.0", 80},
		{"00000000000000000000000001000000:0016", "::1", 22},
		{"00000000000000000000000000000000:01BB", "::", 443},
		{"0000000000000000FFFF00000100007F:0D05", "127.0.0.1", 3333}, // v4-mapped
		{"B80D0120000000000000000001000000:0050", "2001:db8::1", 80},
		{"zz00007F:0016", "", 22},
		{"0100007F", "", 0},
	}
	for _, c := range cases {
		ip, port := parseHexAddr(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("parseHexAddr(%q) = %q, %d; want %q, %d", c.in, ip, port, c.ip, c.port)
		}
	}
}
