//go:build windows

package update

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// updaterMutexSDDL: owned by Administrators, which only an elevated
// process can set, and open to them and SYSTEM only.
const updaterMutexSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"

// adminOwned reports whether the object h is owned by Administrators or
// SYSTEM. Any program may create an object in Global\ (a mutex needs no
// privilege), but not with that owner: one of UpdaterMutex's name that
// such a program made is no updater's, and must not hold every update off.
func adminOwned(h windows.Handle) bool {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)
}

// HoldUpdaterMutex takes UpdaterMutex for a running updater (elevated).
// other: another updater holds it. A mutex of that name an elevated
// process did not make is ignored: the update goes on without it.
func HoldUpdaterMutex() (release func(), other bool, err error) {
	name, err := windows.UTF16PtrFromString(UpdaterMutex)
	if err != nil {
		return nil, false, err
	}
	sd, err := windows.SecurityDescriptorFromString(updaterMutexSDDL)
	if err != nil {
		return nil, false, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(sa, true, name)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// Not elevated (tests): Administrators cannot be the owner.
		h, err = windows.CreateMutex(nil, true, name)
	}
	switch {
	case err == nil:
		return func() { windows.CloseHandle(h) }, false, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		defer windows.CloseHandle(h)
		return func() {}, adminOwned(h), nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// An updater's mutex lets Administrators read its owner: one
		// that cannot be read is not an updater's.
		o, oerr := windows.OpenMutex(windows.READ_CONTROL, false, name)
		if oerr != nil {
			return func() {}, false, nil
		}
		defer windows.CloseHandle(o)
		return func() {}, adminOwned(o), nil
	}
	return nil, false, err
}

// UpdaterRunning reports whether an updater holds UpdaterMutex.
func UpdaterRunning() bool {
	name, err := windows.UTF16PtrFromString(UpdaterMutex)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.READ_CONTROL|windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return adminOwned(h)
}
