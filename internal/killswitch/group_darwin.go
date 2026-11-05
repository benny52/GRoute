//go:build darwin

package killswitch

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// GroupName is the group HyRoute's service and cores run with: the kill
// switch lets its sockets through.
const GroupName = "_hyroute"

// GroupID looks the group up (0 when it does not exist).
func GroupID() int {
	g, err := user.LookupGroup(GroupName)
	if err != nil {
		return 0
	}
	id, _ := strconv.Atoi(g.Gid)
	return id
}

// EnsureGroup creates the group (as root, at the service's install) with
// a free ID below 500, where macOS keeps its system groups.
func EnsureGroup() (int, error) {
	if id := GroupID(); id > 0 {
		return id, nil
	}
	out, err := exec.Command("/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID").Output()
	if err != nil {
		return 0, fmt.Errorf("dscl: %w", err)
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			if n, err := strconv.Atoi(f[1]); err == nil {
				used[n] = true
			}
		}
	}
	id := 0
	for n := 480; n >= 300; n-- {
		if !used[n] {
			id = n
			break
		}
	}
	if id == 0 {
		return 0, fmt.Errorf("нет свободного номера группы для %s", GroupName)
	}
	path := "/Groups/" + GroupName
	for _, args := range [][]string{
		{".", "-create", path},
		{".", "-create", path, "PrimaryGroupID", strconv.Itoa(id)},
		{".", "-create", path, "RealName", "HyRoute"},
		{".", "-create", path, "Password", "*"},
	} {
		if o, err := exec.Command("/usr/bin/dscl", args...).CombinedOutput(); err != nil {
			return 0, fmt.Errorf("dscl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(o)))
		}
	}
	return id, nil
}

// DeleteGroup removes the group (the service's uninstall).
func DeleteGroup() {
	exec.Command("/usr/bin/dscl", ".", "-delete", "/Groups/"+GroupName).Run()
}
