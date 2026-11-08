package hysteria

import "io"

// Child is a process HyRoute started next to its cores (winws2 of the DPI
// bypass). On Windows it is in HyRoute's KILL_ON_JOB_CLOSE job: it never
// outlives HyRoute.
type Child interface {
	Wait() error
	Kill() error
}

// StartChild starts exe like a core: no window, output to out.
func StartChild(exe string, args, env []string, out io.Writer) (Child, error) {
	return startProcess(exe, args, env, out)
}
