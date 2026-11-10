package zapret

import (
	"strconv"
	"strings"
	"time"
)

// SwitchPrefix starts the lines hyroute_circular (LuaFile) writes on
// winws2's output: each method the circular orchestrator takes for a host
// key, the first one and each switch after failures. The Runner keeps
// them apart from winws2's own lines (Switches) for the page («what runs
// now»).
const SwitchPrefix = "HYROUTE\tswitch\t"

// Switch is one such line.
type Switch struct {
	At     time.Time
	Target Target
	// Key: the orchestrator's host key: a domain (youtube.com,
	// googlevideo.com, an own site) or "video:<cluster>".
	Key string
	// Strategy: the method's place in the plan (1…); From: the one before
	// (0: the first for this key since winws2 started).
	Strategy, From int
}

// ParseSwitch reads a line of winws2's output (ok false: not one).
func ParseSwitch(l string) (Switch, bool) {
	rest, ok := strings.CutPrefix(l, SwitchPrefix)
	if !ok {
		return Switch{}, false
	}
	p := strings.Split(rest, "\t")
	if len(p) != 5 {
		return Switch{}, false
	}
	at, err1 := strconv.ParseInt(p[0], 10, 64)
	n, err2 := strconv.Atoi(p[3])
	from, err3 := strconv.Atoi(p[4])
	if err1 != nil || err2 != nil || err3 != nil || n < 1 || from < 0 || p[2] == "" {
		return Switch{}, false
	}
	return Switch{At: time.Unix(at, 0), Target: Target(p[1]), Key: p[2], Strategy: n, From: from}, true
}

// keepSwitches: how many of the orchestrator's lines the Runner keeps.
const keepSwitches = 2000

// Switches are the orchestrator's lines of the current winws2 (Start
// empties them), oldest first.
func (r *Runner) Switches() []Switch {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Switch(nil), r.switches...)
}
