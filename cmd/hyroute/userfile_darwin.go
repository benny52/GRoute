//go:build darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lardan099/hyroute/internal/store"
)

// fileUser is the account of the window that picked a file in its dialog
// (LOCAL_PEERCRED of its connection). The service runs as root and the
// path is the window's answer: the file is written and read with that
// account's rights, by a shell of its own, never by root (only a root
// window gets root's).
type fileUser struct {
	ok     bool
	uid    uint32
	groups []uint32 // the first is the primary group
}

var errDialogGone = errors.New("окно, в котором выбран файл, закрылось: повторите")

// command runs name as u: Go's child drops to u's groups and uid before
// it executes name.
func (u fileUser) command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cred := &syscall.Credential{Uid: u.uid, Gid: u.groups[0], Groups: u.groups[1:]}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return cmd
}

// writeScript writes stdin beside $1 and renames it over $1: a link in
// the file's place is replaced, not followed.
const writeScript = `umask 077 && t="$1.hyroute-$$" && cat > "$t" && mv -f -- "$t" "$1" || { rm -f -- "$t"; exit 1; }`

// readScript prints $1 when it is a regular file.
const readScript = `[ -f "$1" ] || { echo "не обычный файл" >&2; exit 1; }; exec cat -- "$1"`

func (u fileUser) check(path string) (string, error) {
	if !u.ok || len(u.groups) == 0 {
		return "", errDialogGone
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("«%s»: нужен полный путь", path)
	}
	return path, nil
}

// writeUserFile writes b to path, a file u picked.
func (g *GUI) writeUserFile(u fileUser, path string, b []byte) error {
	path, err := u.check(path)
	if err != nil {
		return err
	}
	if u.uid == 0 {
		return store.WriteUserFile(path, b)
	}
	cmd := u.command("/bin/sh", "-c", writeScript, "sh", path)
	cmd.Stdin = bytes.NewReader(b)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("файл «%s» не записан: %s", path, firstLine(out, err))
	}
	return nil
}

// readUserFile reads at most max bytes of path, a regular file u picked.
func (g *GUI) readUserFile(u fileUser, path string, max int64) ([]byte, error) {
	path, err := u.check(path)
	if err != nil {
		return nil, err
	}
	if u.uid == 0 {
		return store.ReadUserFile(path, max)
	}
	cmd := u.command("/bin/sh", "-c", readScript, "sh", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(out, max+1))
	if int64(len(b)) > max {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, store.ErrUserFileTooLarge
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("файл «%s» не прочитан: %s", path, firstLine(stderr.Bytes(), err))
	}
	if rerr != nil {
		return nil, rerr
	}
	return b, nil
}

func firstLine(out []byte, err error) string {
	s := strings.TrimSpace(string(out))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return err.Error()
	}
	return s
}
