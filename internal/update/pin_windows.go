//go:build windows

package update

import (
	"os"
	"path/filepath"

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
		h, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
		if err != nil {
			return &os.PathError{Op: "pin", Path: p, Err: err}
		}
		hs = append(hs, h)
		return nil
	}
	if err := open(path, false); err != nil {
		return nil, err
	}
	vol := filepath.VolumeName(path)
	for d := filepath.Dir(path); len(d) > len(vol)+1 && d != filepath.Dir(d); d = filepath.Dir(d) {
		if err := open(d, true); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}
