//go:build windows

package update

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// PinFile keeps the file at path and every folder above it in place until
// release: they are held open without FILE_SHARE_DELETE (the file also
// without FILE_SHARE_WRITE), so no program can rename, replace or delete
// them, and path keeps naming this very file.
//
// An elevated HyRoute starts its own file again (the window process, a
// copy moved to Program Files, the updater's restart). From a folder that
// programs without administrator rights may write (Downloads), one of them
// could rename HyRoute.exe, or a folder above it, put its own program in
// its place and have it started with the administrator's rights. Pinned,
// the path stays the file HyRoute started from.
func PinFile(path string) (release func(), err error) {
	return pinFile(path, false)
}

// PinPlainFile also requires a local drive path without reparse points.
// The SCM loads a kernel driver by name: verification must describe the
// file that Windows will find through that exact path, even in a folder
// that an ordinary Windows user can write.
func PinPlainFile(path string) (func(), error) {
	if !filepath.IsAbs(path) || len(filepath.VolumeName(path)) != 2 {
		return nil, fmt.Errorf("требуется полный локальный путь к файлу: %q", path)
	}
	return pinFile(path, true)
}

func pinFile(path string, plain bool) (release func(), err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var hs []windows.Handle
	release = func() {
		for _, h := range hs {
			windows.CloseHandle(h)
		}
		hs = nil
	}
	open := func(p string, dir bool) error {
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		access, share, flags := uint32(windows.GENERIC_READ), uint32(windows.FILE_SHARE_READ), uint32(windows.FILE_ATTRIBUTE_NORMAL)
		if dir {
			// Listing access takes part in sharing; files may still be
			// added to and removed from the folder.
			access, share, flags = windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_FLAG_BACKUP_SEMANTICS
		}
		if plain {
			flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
		}
		h, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			return &os.PathError{Op: "pin", Path: p, Err: err}
		}
		hs = append(hs, h)
		if plain {
			var info windows.ByHandleFileInformation
			if err := windows.GetFileInformationByHandle(h, &info); err != nil {
				return err
			}
			if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
				(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
				return fmt.Errorf("путь к драйверу включает ссылку или имеет неверный тип: %s", p)
			}
		}
		return nil
	}
	// Anchor the path from the root down before reading its leaf.
	var parents []string
	vol := filepath.VolumeName(path)
	for d := filepath.Dir(path); len(d) > len(vol)+1 && d != filepath.Dir(d); d = filepath.Dir(d) {
		parents = append(parents, d)
	}
	for _, d := range slices.Backward(parents) {
		if err := open(d, true); err != nil {
			release()
			return nil, err
		}
	}
	if err := open(path, false); err != nil {
		release()
		return nil, err
	}
	if plain {
		// An initially empty ancestor could have become a junction between
		// pinning that directory and opening its child. Once the pinned
		// regular leaf is at the requested path the chain cannot be emptied.
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetFinalPathNameByHandle(hs[len(hs)-1], &buf[0], uint32(len(buf)), 0)
		if err != nil || int(n) >= len(buf) || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(buf), `\\?\`), path) {
			release()
			return nil, fmt.Errorf("не удалось закрепить обычный путь к драйверу %s", path)
		}
	}
	return release, nil
}
