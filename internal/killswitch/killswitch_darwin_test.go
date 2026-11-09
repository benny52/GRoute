//go:build darwin

package killswitch

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestRulesText(t *testing.T) {
	r := Rules(321)
	for _, want := range []string{"pass out quick group 321 flags any keep state", "block drop quick all", "user _mdnsresponder", "<hyroute_tun>",
		// Connections open before the switch: no SYN-only state.
		"pass quick on lo0 all no state", "pass out quick from <hyroute_tun> no state"} {
		if !strings.Contains(r, want) {
			t.Fatalf("%q missing:\n%s", want, r)
		}
	}
	if strings.Index(r, "table <hyroute_tun>") > strings.Index(r, "pass quick on lo0") {
		t.Fatal("tables after rules")
	}
}

// TestPF loads the rules into the real pf and checks that they block a
// process outside HyRoute's group and let one in it through. Root, CI
// only (HYROUTE_PF_TEST=1): it closes the machine's internet for a while.
func TestPF(t *testing.T) {
	if os.Getenv("HYROUTE_PF_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs root and HYROUTE_PF_TEST=1")
	}
	const gid = 4242
	k := &Switch{GID: gid, StateDir: t.TempDir()}
	curl := func(group uint32) error {
		cmd := exec.Command("curl", "-sS", "-m", "8", "-o", "/dev/null", "https://example.com/")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: group}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("curl as group %d: %v %s", group, err, out)
		}
		return err
	}
	if err := curl(0); err != nil {
		t.Fatal("no internet before the test")
	}
	if err := k.Arm(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Release() })
	if on, _ := Leftover(); !on {
		out, _ := exec.Command(pfctl, "-a", Anchor, "-s", "rules").CombinedOutput()
		t.Fatalf("rules not seen:\n%s", out)
	}
	if err := curl(0); err == nil {
		t.Fatal("a process outside the group got through")
	}
	if err := curl(gid); err != nil {
		t.Fatal("HyRoute's group was blocked")
	}
	if err := k.Release(); err != nil {
		t.Fatal(err)
	}
	if on, _ := Leftover(); on {
		t.Fatal("rules left after Release")
	}
	if err := curl(0); err != nil {
		t.Fatal("still blocked after Release")
	}
}
