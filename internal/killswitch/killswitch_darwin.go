//go:build darwin

package killswitch

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// On macOS the kill switch is a pf anchor (com.apple/hyroute, under the
// com.apple/* anchor of the system's main ruleset). One rule set serves
// both states, because the routes do what the Windows pass filter does:
//
//   - passed: loopback, the local network, DHCP, DNS of the system
//     resolver (user _mdnsresponder), HyRoute's own TUN device (its
//     addresses, TUNAddrs), and every socket of group _hyroute (the HyRoute service runs with that group,
//     and so do the cores it starts: their direct connections and the
//     servers);
//   - blocked: everything else, in and out.
//
// While HyRoute routes, applications' traffic goes into its utun device
// and passes; what HyRoute sends on is its own. Once the service stops
// without a Disconnect (a crash, a kill), the kernel removes the device
// and its routes, and the block takes effect: nothing goes past the
// tunnel until HyRoute connects again or the user opens the internet.
// The rules stay in pf until HyRoute removes them or the Mac restarts.
//
// pf is enabled with a reference (pfctl -E) whose token is kept in
// StateDir, so Release gives back exactly HyRoute's reference.
type Switch struct {
	// GID is the group of HyRoute's sockets (group _hyroute).
	GID int
	// StateDir keeps the pf token (root's data folder).
	StateDir string

	mu sync.Mutex
}

// Anchor is HyRoute's pf anchor.
const Anchor = "com.apple/hyroute"

const pfctl = "/sbin/pfctl"

// TUNAddrs are the addresses of HyRoute's TUN device (engine): what
// applications send into it and what HyRoute writes back.
var TUNAddrs = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/30"),
	netip.MustParsePrefix("fdfe:dcba:9876::/126"),
}

// Rules is the anchor's rule set for gid (tables first, as pf.conf
// orders them).
func Rules(gid int) string {
	list := func(ps []netip.Prefix) string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.String()
		}
		return strings.Join(out, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table <hyroute_lan> const { %s }\n", list(LAN))
	fmt.Fprintf(&b, "table <hyroute_tun> const { %s }\n", list(TUNAddrs))
	// pf's pass keeps state and takes TCP only from its SYN (flags S/SA):
	// connections open before the switch was armed (it can be turned on
	// while connected) would hang. Loopback and the device's addresses
	// pass without state; the rest keep state from any packet.
	b.WriteString("pass quick on lo0 all no state\n")
	b.WriteString("pass out quick from <hyroute_tun> no state\n")
	b.WriteString("pass in quick to <hyroute_tun> no state\n")
	fmt.Fprintf(&b, "pass out quick group %d flags any keep state\n", gid)
	b.WriteString("pass out quick to <hyroute_lan> flags any keep state\n")
	b.WriteString("pass in quick from <hyroute_lan> flags any keep state\n")
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n")
	b.WriteString("pass in quick inet proto udp from any port 67 to any port 68\n")
	b.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547\n")
	b.WriteString("pass in quick inet6 proto udp from any port 547 to any port 546\n")
	b.WriteString("pass out quick proto { udp tcp } to any port 53 user _mdnsresponder\n")
	b.WriteString("block drop quick all\n")
	return b.String()
}

// Arm installs the rules (or keeps them): the routes into HyRoute's
// device decide what passes while it works.
func (k *Switch) Arm(uint16) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.GID <= 0 {
		return errors.New("группа _hyroute не найдена: переустановите службу HyRoute (откройте HyRoute.app)")
	}
	if err := ensureMainAnchor(); err != nil {
		return err
	}
	cmd := exec.Command(pfctl, "-a", Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(Rules(k.GID))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pf: правила kill switch не загружены: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return k.enableLocked()
}

// Close: the engine is gone; the rules already block what is not
// HyRoute's.
func (k *Switch) Close() error { return nil }

// Release removes the rules and HyRoute's pf reference.
func (k *Switch) Release() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if out, err := exec.Command(pfctl, "-a", Anchor, "-F", "all").CombinedOutput(); err != nil && !bytes.Contains(out, []byte("No such")) {
		return fmt.Errorf("pf: правила kill switch не удалены: %v: %s", err, strings.TrimSpace(string(out)))
	}
	k.disableLocked()
	return nil
}

// Engaged reports whether the anchor holds rules (maybe left by a run that
// ended without a Disconnect).
func (k *Switch) Engaged() (bool, error) {
	return Leftover()
}

// Leftover reports HyRoute's rules in pf.
func Leftover() (bool, error) {
	out, err := exec.Command(pfctl, "-a", Anchor, "-s", "rules").Output()
	if err != nil {
		return false, nil // no anchor: nothing installed
	}
	return bytes.Contains(out, []byte("block drop")), nil
}

// ensureMainAnchor checks that the main ruleset evaluates the com.apple/*
// anchors (the system's /etc/pf.conf does); a main ruleset another
// program replaced gets the system's back.
func ensureMainAnchor() error {
	out, _ := exec.Command(pfctl, "-s", "rules").Output()
	if bytes.Contains(out, []byte(`anchor "com.apple/*"`)) {
		return nil
	}
	if o, err := exec.Command(pfctl, "-f", "/etc/pf.conf").CombinedOutput(); err != nil {
		return fmt.Errorf("pf: основные правила не загружены: %v: %s", err, strings.TrimSpace(string(o)))
	}
	return nil
}

var tokenRe = regexp.MustCompile(`Token : (\d+)`)

func (k *Switch) tokenPath() string { return filepath.Join(k.StateDir, "pf-token") }

// enableLocked enables pf with HyRoute's own reference (once).
func (k *Switch) enableLocked() error {
	if b, err := os.ReadFile(k.tokenPath()); err == nil && tokenAlive(strings.TrimSpace(string(b))) {
		return nil
	}
	out, err := exec.Command(pfctl, "-E").CombinedOutput()
	m := tokenRe.FindSubmatch(out)
	if err != nil || m == nil {
		return fmt.Errorf("pf не включился: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return os.WriteFile(k.tokenPath(), m[1], 0o600)
}

func (k *Switch) disableLocked() {
	b, err := os.ReadFile(k.tokenPath())
	if err != nil {
		return
	}
	exec.Command(pfctl, "-X", strings.TrimSpace(string(b))).Run()
	os.Remove(k.tokenPath())
}

// tokenAlive: pf still holds the reference (a restart drops them all).
func tokenAlive(tok string) bool {
	if tok == "" {
		return false
	}
	out, _ := exec.Command(pfctl, "-s", "References").Output()
	for _, f := range strings.Fields(string(out)) {
		if f == tok {
			return true
		}
	}
	return false
}
