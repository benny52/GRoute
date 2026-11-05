//go:build darwin

package engine

import (
	"net/netip"
	"testing"
)

func TestBuildICMP(t *testing.T) {
	echo := []byte{0, 0, 0x55, 0xaa, 0x12, 0x34, 0, 1, 'h', 'i'}
	b := buildICMPv4(netip.MustParseAddr("1.1.1.1"), tunAddr4, echo)
	if len(b) != 30 || fold16(sum16(b[:20], 0)) != 0xffff || string(b[20:]) != string(echo) {
		t.Fatalf("v4 % x", b)
	}
	echo6 := []byte{129, 0, 0, 0, 0x12, 0x34, 0, 1, 'h', 'i'}
	b = buildICMPv6(netip.MustParseAddr("2001:db8::1"), tunAddr6, echo6)
	// The checksum over the pseudo-header and the message folds to ones.
	var pseudo [40]byte
	copy(pseudo[0:], b[8:40])
	pseudo[35] = byte(len(echo6))
	pseudo[39] = protoICMPv6
	if fold16(sum16(b[40:], sum16(pseudo[:], 0))) != 0xffff {
		t.Fatalf("v6 checksum % x", b)
	}
	f := &icmpForwarder{}
	if f.handle([]byte{0x45}) || !f.handle(buildICMPv4(tunAddr4, netip.MustParseAddr("1.1.1.1"), []byte{3, 0, 0, 0, 0, 0, 0, 0})) {
		t.Fatal("handle: short is not ICMP; a non-echo ICMP is taken and dropped")
	}
}
