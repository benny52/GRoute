package attrib

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

// pcbItems builds a pcblist_n buffer the way the kernel lays it out, with
// xsocket_n packed (pack 4) or aligned.
func pcbItems(packed bool, socks ...PCB) []byte {
	le := binary.LittleEndian
	gen := make([]byte, 24)
	le.PutUint32(gen, 24)
	le.PutUint32(gen[4:], uint32(len(socks)))
	buf := append([]byte(nil), gen...)
	pad := func(b []byte) []byte {
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
		return b
	}
	for _, s := range socks {
		// struct xinpcb_n as macOS 26 lays it out (pack 4).
		in := make([]byte, 104)
		le.PutUint32(in, uint32(len(in)))
		le.PutUint32(in[4:], xsoInpcb)
		binary.BigEndian.PutUint16(in[16:], s.Remote.Port())
		binary.BigEndian.PutUint16(in[18:], s.Local.Port())
		le.PutUint64(in[28:], 200) // inp_gencnt
		put := func(at []byte, a netip.Addr) {
			if a.Is4() {
				a4 := a.As4()
				copy(at[12:], a4[:])
				return
			}
			a16 := a.As16()
			copy(at, a16[:])
		}
		if s.Local.Addr().Is4() {
			in[44] = inpIPv4
		} else {
			in[44] = inpIPv6
		}
		in[45] = 64 // ttl
		put(in[48:], s.Remote.Addr())
		put(in[64:], s.Local.Addr())
		buf = pad(append(buf, in...))

		size, proto, pids := 112, 40, 68
		if packed {
			size, proto, pids = 100, 36, 64
		}
		so := make([]byte, size)
		le.PutUint32(so, uint32(size))
		le.PutUint32(so[4:], xsoSocket)
		le.PutUint32(so[proto:], 6)
		fam := uint32(2)
		if !s.Local.Addr().Is4() {
			fam = 30
		}
		le.PutUint32(so[proto+4:], fam)
		le.PutUint32(so[pids:], s.PID)
		buf = pad(append(buf, so...))
		// Socket buffers and stats: other kinds, skipped.
		other := make([]byte, 40)
		le.PutUint32(other, 40)
		le.PutUint32(other[4:], 0x002)
		buf = append(buf, other...)
	}
	return append(buf, gen...)
}

func TestParsePCBList(t *testing.T) {
	socks := []PCB{
		{Local: netip.MustParseAddrPort("198.18.0.1:50000"), Remote: netip.MustParseAddrPort("93.184.216.34:443"), PID: 501},
		{Local: netip.MustParseAddrPort("[2001:db8::1]:50001"), Remote: netip.MustParseAddrPort("[2001:db8::2]:443"), PID: 777},
		{Local: netip.MustParseAddrPort("0.0.0.0:5353"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), PID: 90},
	}
	for _, packed := range []bool{false, true} {
		got := ParsePCBList(pcbItems(packed, socks...))
		if len(got) != len(socks) {
			t.Fatalf("packed=%v: %+v", packed, got)
		}
		for i := range socks {
			if got[i] != socks[i] {
				t.Fatalf("packed=%v: %+v != %+v", packed, got[i], socks[i])
			}
		}
	}
	if ParsePCBList(nil) != nil || ParsePCBList(make([]byte, 7)) != nil {
		t.Fatal("short buffer")
	}
	// A truncated buffer yields what it holds, without a panic.
	b := pcbItems(false, socks...)
	for n := range len(b) {
		ParsePCBList(b[:n])
	}
}

func TestMatchPCB(t *testing.T) {
	pcbs := []PCB{
		{Local: netip.MustParseAddrPort("198.18.0.1:50000"), Remote: netip.MustParseAddrPort("93.184.216.34:443"), PID: 1},
		{Local: netip.MustParseAddrPort("0.0.0.0:6000"), PID: 2},
		{Local: netip.MustParseAddrPort("198.18.0.1:7000"), Remote: netip.MustParseAddrPort("1.1.1.1:53"), PID: 3},
		{Local: netip.MustParseAddrPort("0.0.0.0:7000"), PID: 4},
		{Local: netip.MustParseAddrPort("0.0.0.0:8000"), PID: 5},
		{Local: netip.MustParseAddrPort("[::]:8000"), PID: 6},
	}
	ap := netip.MustParseAddrPort
	if pid, ok := MatchTCP(pcbs, ap("198.18.0.1:50000"), ap("93.184.216.34:443")); !ok || pid != 1 {
		t.Fatal(pid, ok)
	}
	if _, ok := MatchTCP(pcbs, ap("198.18.0.1:50000"), ap("93.184.216.34:80")); ok {
		t.Fatal("other remote")
	}
	if pid, ok := MatchUDP(pcbs, ap("198.18.0.1:6000"), ap("8.8.8.8:53")); !ok || pid != 2 {
		t.Fatal(pid, ok)
	}
	if pid, ok := MatchUDP(pcbs, ap("198.18.0.1:7000"), ap("1.1.1.1:53")); !ok || pid != 3 {
		t.Fatal("connected first", pid, ok)
	}
	if pid, ok := MatchUDP(pcbs, ap("198.18.0.1:7000"), ap("9.9.9.9:53")); !ok || pid != 4 {
		t.Fatal(pid, ok)
	}
	if _, ok := MatchUDP(pcbs, ap("198.18.0.1:8000"), ap("9.9.9.9:53")); ok {
		t.Fatal("two owners guessed")
	}
}

// Items as a macOS 26 (arm64) kernel wrote them: a connection
// 127.0.0.1:49200 -> 127.0.0.1:49199 of process 3598, run by uid 501.
func TestParsePCBListMacOS26(t *testing.T) {
	inpcb, _ := hex.DecodeString("6800000010000000b0b5c9ea1e33ed77c030c02fdb36e4e609a64d06c8000000000000000000800000010d00014000000000000000000000000000007f0000010000000000000000000000007f0000010000000000000000000000000000000039f2d18212000000")
	sock, _ := hex.DecodeString("68000000010000005727bf0273d89089010000000400000000000311b0b5c9ea1e33ed7706000000020000000000000000000000000000000000000000000000f50100000e0e000000000000970e0000000000008000000000080001020000000000000000000000")
	gen := make([]byte, 24)
	binary.LittleEndian.PutUint32(gen, 24)
	buf := append(append(append(append([]byte(nil), gen...), inpcb...), sock...), gen...)
	got := ParsePCBList(buf)
	want := PCB{Local: netip.MustParseAddrPort("127.0.0.1:49199"), Remote: netip.MustParseAddrPort("127.0.0.1:49200"), PID: 3598}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("%+v", got)
	}
}
