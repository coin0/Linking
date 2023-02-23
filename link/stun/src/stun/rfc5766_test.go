package stun

import (
	"testing"
	"net"
	"encoding/binary"
)

// -------------------------------------------------------------------------------------------------

func Test_Func_keygen_ipv4_in_ipv6_format(t *testing.T) {

	addr := &address{
		Proto: NET_TLS,
		Port: 12345,
		IP: net.ParseIP("::ffff:7fff:ffff"),
	}

	key := keygen(addr)
	if !key.IPv4 {
		t.Fatal("should be an IPv4 address")
	}
	ip := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(ip, key.IP[0])
	if !net.IPv4(ip[0], ip[1], ip[2], ip[3]).Equal(net.ParseIP("127.255.255.255")) {
		t.Fatal("ipv4 address mismatch")
	}
}
