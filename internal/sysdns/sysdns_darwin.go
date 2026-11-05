//go:build darwin

package sysdns

import (
	"net/netip"
	"os/exec"
)

// Snapshot reads the resolver configuration (scutil --dns).
func Snapshot() (Info, error) {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return Info{}, err
	}
	return ParseScutil(string(out)), nil
}

// Servers are the DNS servers of the resolvers.
func Servers() (map[netip.Addr]bool, error) {
	i, err := Snapshot()
	return i.All, err
}
