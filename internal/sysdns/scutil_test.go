package sysdns

import (
	"net/netip"
	"testing"
)

const scutilOut = `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 12 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 9.9.9.9
  if_index : 12 (en0)
  flags    : Scoped, Request A records
`

func TestParseScutil(t *testing.T) {
	i := ParseScutil(scutilOut)
	a := netip.MustParseAddr
	if !i.Primary[a("192.168.1.1")] || !i.Primary[a("fe80::1")] || i.Primary[a("9.9.9.9")] || !i.All[a("9.9.9.9")] || len(i.All) != 3 {
		t.Fatalf("%+v", i)
	}
	if !i.Local("router.lan") || !i.Local("printer.local") || i.Local("example.com") {
		t.Fatalf("suffixes %v", i.Suffixes)
	}
}
