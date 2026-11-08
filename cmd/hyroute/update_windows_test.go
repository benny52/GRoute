package main

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/update"
)

// A running hyroute-updater holds its mutex: HyRoute sees it and does not
// start a second one.
func TestUpdaterRunning(t *testing.T) {
	if updaterRunning() {
		t.Skip("an updater runs on this machine")
	}
	name, _ := windows.UTF16PtrFromString(update.UpdaterMutex)
	h, err := windows.CreateMutex(nil, true, name)
	if err != nil {
		t.Skipf("no global mutex here: %v", err)
	}
	if !updaterRunning() {
		t.Fatal("the updater's mutex is not seen")
	}
	windows.CloseHandle(h)
	if updaterRunning() {
		t.Fatal("seen after it was released")
	}
	g := &GUI{}
	g.updating.Store(true)
	if err := g.ApplyAppUpdate(); err == nil {
		t.Fatal("a second update while the first one runs")
	}
}
