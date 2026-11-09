package tgws

import (
	"fmt"
	"net/netip"
)

// Telegram's data centers: their main addresses (the direct TCP fallback)
// and the test ones.
var (
	dcAddr = map[int]netip.Addr{
		1:   netip.MustParseAddr("149.154.175.50"),
		2:   netip.MustParseAddr("149.154.167.51"),
		3:   netip.MustParseAddr("149.154.175.100"),
		4:   netip.MustParseAddr("149.154.167.91"),
		5:   netip.MustParseAddr("149.154.171.5"),
		203: netip.MustParseAddr("91.105.192.100"),
	}
	dcTestAddr = map[int]netip.Addr{
		1: netip.MustParseAddr("149.154.175.10"),
		2: netip.MustParseAddr("149.154.167.40"),
		3: netip.MustParseAddr("149.154.175.117"),
	}
)

// DefaultRedirect: the address the WebSocket endpoints of a data center
// are reached at. Telegram serves kws2 and kws4 there; the other data
// centers go by the fallbacks (as in tg-ws-proxy).
func DefaultRedirect() map[int]netip.Addr {
	a := netip.MustParseAddr("149.154.167.220")
	return map[int]netip.Addr{2: a, 4: a}
}

// wsHosts are the WebSocket names of a data center, media first (kwsN-1).
func wsHosts(dc int, media bool) []string {
	if dc == 203 {
		dc = 2
	}
	h := fmt.Sprintf("kws%d.web.telegram.org", dc)
	if media {
		return []string{fmt.Sprintf("kws%d-1.web.telegram.org", dc), h}
	}
	return []string{h}
}

// directAddr is the TCP address of a data center (ok false: unknown).
func directAddr(dc int, test bool) (netip.AddrPort, bool) {
	m := dcAddr
	if test {
		m = dcTestAddr
	}
	a, ok := m[dc]
	return netip.AddrPortFrom(a, 443), ok
}

// FrontingSNI is the name sent instead of kwsN.web.telegram.org when that
// name itself is blocked: the server answers by Host.
const FrontingSNI = "sprinthost.ru"

// FrontingCertName: the name Telegram's default certificate is valid for,
// which it presents to a TLS name it does not serve.
const FrontingCertName = "telegram.org"
