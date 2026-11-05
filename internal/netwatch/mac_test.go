package netwatch

import (
	"testing"

	"github.com/lardan099/hyroute/internal/netmode"
)

func TestParseHardwarePorts(t *testing.T) {
	out := `
Hardware Port: Ethernet
Device: en0
Ethernet Address: 00:11:22:33:44:55

Hardware Port: Wi-Fi
Device: en1
Ethernet Address: 66:77:88:99:aa:bb

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: N/A

Hardware Port: iPhone USB
Device: en5
Ethernet Address: 00:00:00:00:00:00

VLAN Configurations
===================
`
	p := parseHardwarePorts(out)
	want := map[string]macPort{
		"en0":     {"Ethernet", netmode.Ethernet},
		"en1":     {"Wi-Fi", netmode.WiFi},
		"bridge0": {"Thunderbolt Bridge", netmode.Ethernet},
		"en5":     {"iPhone USB", netmode.Mobile},
	}
	if len(p) != len(want) {
		t.Fatalf("%v", p)
	}
	for d, w := range want {
		if p[d] != w {
			t.Errorf("%s: %+v", d, p[d])
		}
	}
}

func TestParseARP(t *testing.T) {
	for out, want := range map[string]string{
		"? (192.168.1.1) at 0:11:2:a3:44:5 on en0 ifscope [ethernet]\n": "00:11:02:A3:44:05",
		"? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]\n":   "",
		"192.168.1.1 (192.168.1.1) -- no entry\n":                       "",
		"? (10.0.0.1) at 0:0:0:0:0:0 on en0 [ethernet]\n":               "",
	} {
		if got := parseARP(out); got != want {
			t.Errorf("%q: %q", out, got)
		}
	}
}

func TestParseSummarySSID(t *testing.T) {
	cases := []struct {
		out  string
		ssid string
		err  error
	}{
		{"<dictionary> {\n  BSSID : 11:22:33:44:55:66\n  SSID : Home Net\n}", "Home Net", nil},
		{"<dictionary> {\n  SSID : <redacted>\n}", "", netmode.ErrSSIDDenied},
		{"<dictionary> {\n  InterfaceType : Ethernet\n}", "", nil},
	}
	for _, c := range cases {
		s, err := parseSummarySSID(c.out)
		if s != c.ssid || err != c.err {
			t.Errorf("%q: %q %v", c.out, s, err)
		}
	}
}

func TestMacNetID(t *testing.T) {
	a, b := macNetID("00:11:22:33:44:55"), macNetID("00:11:22:33:44:56")
	if a == "" || a == b || a != macNetID("00:11:22:33:44:55") || macNetID("") != "" {
		t.Fatalf("%s %s", a, b)
	}
	if len(a) != 38 || a[0] != '{' || a[37] != '}' {
		t.Fatalf("not shaped like an NLM ID: %s", a)
	}
}
