//go:build windows

package main

import "github.com/lardan099/hyroute/internal/store"

// fileUser is whose file a dialog picked. On Windows the window is this
// process's own: store's user-file functions check the logged-on user's
// rights themselves (LimitedToken).
type fileUser struct{}

func (h *winHost) dialogUser(string) fileUser { return fileUser{} }

// writeUserFile writes b to path, a file the user picked.
func (g *GUI) writeUserFile(_ fileUser, path string, b []byte) error {
	return store.WriteUserFile(path, b)
}

// readUserFile reads at most max bytes of path, a file the user picked.
func (g *GUI) readUserFile(_ fileUser, path string, max int64) ([]byte, error) {
	return store.ReadUserFile(path, max)
}
