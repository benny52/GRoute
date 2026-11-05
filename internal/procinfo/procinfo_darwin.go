//go:build darwin

package procinfo

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// NewCache returns a cache backed by the kern.proc and kern.procargs2
// sysctls (root reads every process).
func NewCache() *Cache {
	return NewCacheWith(System{Query: query, Snapshot: snapshot, Created: createdTime})
}

func startTime(k *unix.KinfoProc) int64 {
	return k.Proc.P_starttime.Nano()
}

func createdTime(pid uint32) (created int64, ok, gone bool) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return 0, false, false
	}
	if k.Proc.P_pid != int32(pid) {
		return 0, false, true // no such process: the sysctl returns an empty record
	}
	return startTime(k), true, false
}

func query(pid uint32) (string, int64, bool) {
	created, ok, _ := createdTime(pid)
	if !ok {
		return "", 0, false
	}
	return execPath(pid), created, true
}

// execPath is the executable the process started from: kern.procargs2 is
// argc, then the path, then the arguments.
func execPath(pid uint32) string {
	buf, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(buf) < 5 {
		return ""
	}
	_ = binary.LittleEndian.Uint32(buf) // argc
	rest := buf[4:]
	if i := bytes.IndexByte(rest, 0); i > 0 {
		return string(rest[:i])
	}
	return ""
}

func snapshot() []ProcEntry {
	all, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	out := make([]ProcEntry, 0, len(all))
	for i := range all {
		k := &all[i]
		out = append(out, ProcEntry{PID: uint32(k.Proc.P_pid), PPID: uint32(k.Eproc.Ppid), Created: startTime(k)})
	}
	return out
}
