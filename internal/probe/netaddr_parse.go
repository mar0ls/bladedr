package probe

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// parseHexAddr decodes a /proc/net/tcp{,6} "ADDR:PORT" field. The kernel prints the
// address as 32-bit words in host byte order (%08X of a network-order value loaded as
// a native integer), so on little-endian hosts 127.0.0.1 reads "0100007F". Decoding
// the hex as bytes yields them reversed; each word has to be parsed as a number and
// stored back in native order. IPv6 is four such words, not a byte string.
func parseHexAddr(s string) (string, int) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0
	}
	port, _ := strconv.ParseInt(portHex, 16, 32)
	if len(host) != 8 && len(host) != 32 {
		return "", int(port)
	}
	ip := make(net.IP, len(host)/2)
	for i := 0; i < len(host); i += 8 {
		word, err := strconv.ParseUint(host[i:i+8], 16, 32)
		if err != nil {
			return "", int(port)
		}
		binary.NativeEndian.PutUint32(ip[i/2:], uint32(word))
	}
	return ip.String(), int(port)
}
