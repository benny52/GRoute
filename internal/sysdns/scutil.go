package sysdns

import (
	"bufio"
	"net/netip"
	"strings"
)

// ParseScutil reads the output of macOS "scutil --dns": the DNS servers
// ("nameserver[0] : 192.168.1.1") and search domains of the resolvers.
// The default resolvers (the first section, "DNS configuration") are the
// primary ones; scoped resolvers only add to All. Resolvers for a domain
// ("domain : local", mDNS and the like) add their domain to the local
// namespaces.
func ParseScutil(out string) Info {
	info := Info{Primary: map[netip.Addr]bool{}, All: map[netip.Addr]bool{}}
	scoped := false
	var names []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			scoped = true
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			a, err := netip.ParseAddr(val)
			if err != nil {
				continue
			}
			a = a.Unmap().WithZone("")
			info.All[a] = true
			if !scoped {
				info.Primary[a] = true
			}
		case strings.HasPrefix(key, "search domain["), key == "domain":
			names = append(names, val)
		}
	}
	info.Suffixes = LocalSuffixes(ParseNames(names), nil)
	return info
}
