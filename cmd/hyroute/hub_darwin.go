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

// peerAllowed: root or a member of group admin.
func peerAllowed(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if cred.Uid == 0 {
		return 0, nil
	}
	for _, g := range cred.Groups[:min(int(cred.Ngroups), len(cred.Groups))] {
		if g == adminGID {
			return cred.Uid, nil
		}
	}
	return cred.Uid, fmt.Errorf("пользователь %d не администратор этого Mac", cred.Uid)
}

func (h *winHost) serve(c *net.UnixConn) {
	defer c.Close()
	uid, err := peerAllowed(c)
	if err != nil {
		h.g.ctl.Log.Warn("window connection refused", "uid", uid, "err", err)
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
			if json.Unmarshal(args[0], &p) == nil && filepath.IsAbs(p) && filepath.Base(p) == "HyRoute.app" {
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
	r, err := h.call("dialog.open", o)
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}

func (h *winHost) saveFile(o runtime.SaveDialogOptions) (string, error) {
	r, err := h.call("dialog.save", o)
	if err != nil {
		return "", err
	}
	var s string
	return s, json.Unmarshal(r, &s)
}

// openPath has the window open a folder or a link as its user (Finder,
// the browser): the service is root.
func (h *winHost) openPath(path string) error {
	_, err := h.call("open", path)
	return err
}
