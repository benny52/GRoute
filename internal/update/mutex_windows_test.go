//go:build windows

package update

import (
	"testing"

	"golang.org/x/sys/windows"
)

// An updater's mutex, elevated: a second updater sees it, and HyRoute
// knows one is waiting. Without elevation (no Administrators owner) the
// mutex counts as nobody's.
func TestUpdaterMutex(t *testing.T) {
	release, other, err := HoldUpdaterMutex()
	if err != nil || other {
		t.Fatalf("first: %v %v", other, err)
	}
	defer release()
	elevated := windows.GetCurrentProcessToken().IsElevated()
	_, other, err = HoldUpdaterMutex()
	if err != nil || other != elevated {
		t.Fatalf("second: other %v, elevated %v, %v", other, elevated, err)
	}
	if UpdaterRunning() != elevated {
		t.Fatalf("running %v, elevated %v", UpdaterRunning(), elevated)
	}
}
