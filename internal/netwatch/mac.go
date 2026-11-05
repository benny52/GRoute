package netwatch

// macOS parsers (netwatch_darwin.go), kept untagged so they are tested on
// every system.

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/lardan099/hyroute/internal/netmode"
)

// macPort is a hardware port of networksetup -listallhardwareports.
type macPort struct {
	Name string // "Wi-Fi", "Ethernet", "Thunderbolt Bridge", "iPhone USB"
	Kind string // netmode.WiFi, Ethernet, Mobile, Other
}

// parseHardwarePorts maps devices (en0) to their hardware ports.
func parseHardwarePorts(out string) map[string]macPort {
	ports := map[string]macPort{}
	name := ""
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Hardware Port":
			name = v
		case "Device":
			if name != "" && v != "" {
				ports[v] = macPort{Name: name, Kind: macPortKind(name)}
			}
			name = ""
		}
	}
	return ports
}

func macPortKind(name string) string {
	n := strings.ToLower(name)
	switch {
	case n == "wi-fi" || n == "airport":
		return netmode.WiFi
	case strings.Contains(n, "iphone") || strings.Contains(n, "ipad") || strings.Contains(n, "bluetooth") ||
		strings.Contains(n, "modem") || strings.Contains(n, "wwan"):
		return netmode.Mobile
	case strings.Contains(n, "ethernet") || strings.Contains(n, "lan") || strings.Contains(n, "thunderbolt"):
		return netmode.Ethernet
	}
	return netmode.Other
}

// parseARP reads the MAC of `arp -n <ip>`: "? (192.168.1.1) at
// a:b:c:d:e:f on en0 ifscope [ethernet]"; "" when incomplete.
func parseARP(out string) string {
	_, rest, ok := strings.Cut(out, " at ")
	if !ok {
		return ""
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return ""
	}
	hw, err := net.ParseMAC(padMAC(f[0]))
	if err != nil || len(hw) != 6 || isZero(hw) {
		return ""
	}
	return strings.ToUpper(hw.String())
}

// padMAC: arp prints octets without leading zeros ("0:11:2:…").
func padMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return s
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// errSSIDHidden: macOS gives the Wi-Fi name only to apps allowed to use
// the location, not to services.
var errSSIDHidden = netmode.ErrSSIDDenied

// parseSummarySSID reads the Wi-Fi name of `ipconfig getsummary <if>`
// ("  SSID : name"); errSSIDHidden when macOS redacted it, "" when the
// interface is not on Wi-Fi.
func parseSummarySSID(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if !ok || strings.TrimSpace(k) != "SSID" {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || v == "<redacted>" {
			return "", errSSIDHidden
		}
		return v, nil
	}
	return "", nil
}

// macNetID is «Именно эта сеть» on macOS: the network is known by its
// router, as Windows knows it. The ID is derived from the router's MAC
// (so the MAC itself is not stored), shaped like an NLM ID.
func macNetID(gatewayMAC string) string {
	if gatewayMAC == "" {
		return ""
	}
	h := sha256.Sum256([]byte("hyroute-net\x00" + strings.ToUpper(gatewayMAC)))
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
