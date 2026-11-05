//go:build darwin

package ctl

import (
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// On macOS the command line talks to the HyRoute service over a unix
// socket of root's. The service serves root and the Mac's administrators
// (group admin), as its window socket does; hyroutectl checks that the
// socket is root's before it sends anything.

// MacOwner stands for the owner part of the names on macOS: one service
// serves the whole Mac.
const MacOwner = "macos"

const (
	// SockPath is the command line's socket.
	SockPath = "/var/run/hyroute-ctl.sock"
	// ServiceSock is the window's socket: its presence says the service
	// runs (the run event of Windows).
	ServiceSock = "/var/run/hyroute.sock"
	adminGID    = 80
)

type Listener struct {
	ln *net.UnixListener
}

// ListenUnix serves the command line's socket.
func ListenUnix(path string) (*Listener, error) {
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return &Listener{ln: ln}, nil
}

// Accept returns the next connection and whether its peer may be served:
// root or a member of group admin.
func (l *Listener) Accept() (net.Conn, Identity, bool, error) {
	c, err := l.ln.AcceptUnix()
	if err != nil {
		return nil, Identity{}, false, err
	}
	id := Identity{IntegrityRID: MediumRID}
	raw, err := c.SyscallConn()
	if err != nil {
		return c, id, false, nil
	}
	var cred *unix.Xucred
	var pid int
	raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if cred == nil {
		return c, id, false, nil
	}
	id.User, id.PID = strconv.Itoa(int(cred.Uid)), uint32(pid)
	id.System = cred.Uid == 0
	for _, g := range cred.Groups[:min(int(cred.Ngroups), len(cred.Groups))] {
		if g == adminGID {
			id.Admin = true
		}
	}
	id.Elevated = id.System
	return c, id, id.System || id.Admin, nil
}

func (l *Listener) Close() error { return l.ln.Close() }

// Dial connects to the service's command line socket (name is ignored:
// there is one). A socket that is not root's is an impostor's.
func Dial(_ string, timeout time.Duration, _ []string) (net.Conn, uint32, error) {
	fi, err := os.Lstat(SockPath)
	if err != nil {
		return nil, 0, ErrNotRunning
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || fi.Mode()&os.ModeSocket == 0 {
		return nil, 0, ErrImpostor
	}
	c, err := net.DialTimeout("unix", SockPath, timeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return nil, 0, ErrNotRunning
		}
		return nil, 0, err
	}
	var pid int
	if raw, err := c.(*net.UnixConn).SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) { pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) })
	}
	return c, uint32(pid), nil
}

// FindPipes: there is no other account's HyRoute on a Mac.
func FindPipes() ([]string, error) { return nil, nil }

// ProbeRunEvent tells by the service's window socket whether it runs:
// settled, as there is no starting state worth waiting for.
func ProbeRunEvent(string, []string) (RunState, error) {
	if c, err := net.DialTimeout("unix", ServiceSock, time.Second); err == nil {
		c.Close()
		return RunSettled, nil
	}
	return RunAbsent, nil
}
