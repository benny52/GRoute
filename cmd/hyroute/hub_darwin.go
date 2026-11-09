//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/unix"

	"github.com/lardan099/hyroute/internal/uirpc"
)

// On macOS HyRoute is two programs: the service (root, started by launchd:
// the engine, the controller, everything the Windows main process has)
// and the window (HyRoute.app, the user's own process: Wails). The window
// connects to the service's socket and talks uirpc to it, as the window
// process does over its pipes on Windows. Only an administrator of the
// Mac (group admin) or root may connect: the service routes the whole
// machine.
const sockPath = "/var/run/hyroute.sock"

const adminGID = 80 // group admin

// winHost is the service's side of the windows connected to it.
type winHost struct {
	g *GUI

	mu    sync.Mutex
	peers []*uirpc.Peer // newest last: dialogs and the clipboard go to it
	// menubar: the peers that are the menu bar icon (they asked
	// "client.menubar"): events go to them, dialogs never.
	menubar map[*uirpc.Peer]bool
	// app is the HyRoute.app the newest window runs from (client.app):
	// an update replaces it.
	app string
	ln  net.Listener
	// users: each window's account; dialogs: the account of the window
	// that picked each path in a dialog, until the path is used
	// (dialogUser). Files the user picks are written and read with that
	// account's rights (userfile_darwin.go).
	users   map[*uirpc.Peer]fileUser
	dialogs map[string]fileUser
}

var errNoWindow = errors.New("окно HyRoute закрыто")

// listen serves the socket until the listener is closed.
func (h *winHost) listen() error {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	// Anyone may connect; peerAllowed decides who is served.
	if err := os.Chmod(sockPath, 0o666); err != nil {
		ln.Close()
		return err
	}
	h.mu.Lock()
	h.ln = ln
	h.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(c.(*net.UnixConn))
		}
	}()
	return nil
}

// peerAllowed: root or a member of group admin. The account is the
// peer's, with its groups (the first the primary one).
func peerAllowed(c *net.UnixConn) (fileUser, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return fileUser{}, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return fileUser{}, err
	}
	if cerr != nil {
		return fileUser{}, cerr
	}
	u := fileUser{ok: true, uid: cred.Uid, groups: append([]uint32(nil), cred.Groups[:min(int(cred.Ngroups), len(cred.Groups))]...)}
	if cred.Uid == 0 {
		return u, nil
	}
	for _, g := range u.groups {
		if g == adminGID {
			return u, nil
		}
	}
	return u, fmt.Errorf("пользователь %d не администратор этого Mac", cred.Uid)
}

// userApp reports whether p is a HyRoute.app u may have the service
// replace: no symbolic link on the way, and the bundle u's or root's.
func userApp(p string, u fileUser) bool {
	if !filepath.IsAbs(p) || filepath.Base(p) != "HyRoute.app" {
		return false
	}
	if real, err := filepath.EvalSymlinks(p); err != nil || real != filepath.Clean(p) {
		return false
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == u.uid)
}

func (h *winHost) serve(c *net.UnixConn) {
	defer c.Close()
	user, err := peerAllowed(c)
	if err != nil {
		h.g.ctl.Log.Warn("window connection refused", "uid", user.uid, "err", err)
		// The window shows why.
		p := uirpc.New(c, c)
		go p.Run()
		p.Notify("refused", "HyRoute управляют только администраторы этого Mac: "+err.Error())
		time.Sleep(time.Second)
		return
	}
	p := uirpc.New(c, c)
	p.OnCall = h.answer
	p.OnEvent = func(name string, args []json.RawMessage) {
		if name == "client.app" && len(args) == 1 {
			var p string
			if json.Unmarshal(args[0], &p) == nil && userApp(p, user) {
				h.mu.Lock()
				h.app = p
				h.mu.Unlock()
			}
			return
		}
		if name == "client.menubar" {
			h.mu.Lock()
			if h.menubar == nil {
				h.menubar = map[*uirpc.Peer]bool{}
			}
			h.menubar[p] = true
			h.mu.Unlock()
		}
	}
	h.mu.Lock()
	h.peers = append(h.peers, p)
	if h.users == nil {
		h.users = map[*uirpc.Peer]fileUser{}
	}
	h.users[p] = user
	h.mu.Unlock()
	p.Run()
	h.mu.Lock()
	for i, q := range h.peers {
		if q == p {
			h.peers = append(h.peers[:i], h.peers[i+1:]...)
			break
		}
	}
	delete(h.menubar, p)
	delete(h.users, p)
	h.mu.Unlock()
}

// answer serves a window's call: a method of GUI.
func (h *winHost) answer(method string, args []json.RawMessage) (any, error) {
	if strings.HasPrefix(method, "window.") {
		// The window's own calls: its × closes it (the service stays).
		return "close", nil
	}
	return h.g.dispatch(method, args)
}

// current is the newest window (not a menu bar icon).
func (h *winHost) current() *uirpc.Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.peers) - 1; i >= 0; i-- {
		if !h.menubar[h.peers[i]] {
			return h.peers[i]
		}
	}
	return nil
}

func (h *winHost) isOpen() bool { return h.current() != nil }

// appPath is the HyRoute.app to update ("" when no window said).
func (h *winHost) appPath() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.app
}

func (h *winHost) call(method string, args ...any) (json.RawMessage, error) {
	p := h.current()
	if p == nil {
		return nil, errNoWindow
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return p.Call(ctx, method, args...)
}

// notify sends an event to every window.
func (h *winHost) notify(name string, args ...any) {
	h.mu.Lock()
	peers := append([]*uirpc.Peer(nil), h.peers...)
	h.mu.Unlock()
	for _, p := range peers {
		p.Notify(name, args...)
	}
}

// open brings the newest window to the front (the service cannot start
// one: it runs outside the user's session).
func (h *winHost) open(string) {
	if p := h.current(); p != nil {
		go p.Call(context.Background(), "show")
		return
	}
	// No window: the menu bar icon, the user's process, starts one.
	h.mu.Lock()
	var bars []*uirpc.Peer
	for p := range h.menubar {
		bars = append(bars, p)
	}
	h.mu.Unlock()
	for _, p := range bars {
		p.Notify("menubar.openWindow")
	}
}

func (h *winHost) close() {
	h.mu.Lock()
	ln := h.ln
	h.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	h.notify("service.exit")
}

func (h *winHost) clipboardGet() (string, error) {
	r, err := h.call("clipboard.get")
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}

func (h *winHost) clipboardSet(text string) error {
	_, err := h.call("clipboard.set", text)
	return err
}

func (h *winHost) openFile(o runtime.OpenDialogOptions) (string, error) {
	return h.dialog("dialog.open", o)
}

func (h *winHost) saveFile(o runtime.SaveDialogOptions) (string, error) {
	return h.dialog("dialog.save", o)
}

// dialog asks the newest window for a path and notes whose it is.
func (h *winHost) dialog(method string, o any) (string, error) {
	p := h.current()
	if p == nil {
		return "", errNoWindow
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r, err := p.Call(ctx, method, o)
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil || s == "" {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if u, ok := h.users[p]; ok {
		if h.dialogs == nil || len(h.dialogs) > 16 {
			h.dialogs = map[string]fileUser{} // paths never used
		}
		h.dialogs[s] = u
	}
	return s, nil
}

// dialogUser is the account of the window whose dialog returned path
// (once: the path is forgotten); not ok when none did.
func (h *winHost) dialogUser(path string) fileUser {
	h.mu.Lock()
	defer h.mu.Unlock()
	u := h.dialogs[path]
	delete(h.dialogs, path)
	return u
}

// openPath has the window open a folder or a link as its user (Finder,
// the browser): the service is root.
func (h *winHost) openPath(path string) error {
	_, err := h.call("open", path)
	return err
}
