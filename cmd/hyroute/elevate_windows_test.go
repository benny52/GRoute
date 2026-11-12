package main

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPortableRestartAsAdmin(t *testing.T) {
	g := &GUI{quitCh: make(chan struct{})}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launches := 0
	launch := func(exe string, pid int) error {
		launches++
		if exe != self || pid != os.Getpid() {
			t.Fatal("requested elevation for a different executable or process")
		}
		if launches == 1 {
			return windows.ERROR_CANCELLED
		}
		return nil
	}
	if err := g.restartAsAdmin(false, launch); err == nil || launches != 0 {
		t.Fatal("offered UAC outside an unelevated portable instance")
	}
	if err := g.restartAsAdmin(true, launch); err == nil || g.quitting.Load() {
		t.Fatal("UAC cancellation must leave this instance running", err)
	}
	if err := g.restartAsAdmin(true, launch); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.quitCh:
	default:
		t.Fatal("previous instance did not request a graceful exit")
	}
	if err := g.restartAsAdmin(true, launch); err == nil || launches != 2 {
		t.Fatal("launched a second elevated instance")
	}
}

func TestPortableRestartWaitsForUAC(t *testing.T) {
	g := &GUI{quitCh: make(chan struct{})}
	prompt := make(chan struct{})
	cancel := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- g.restartAsAdmin(true, func(string, int) error {
			close(prompt)
			<-cancel
			return windows.ERROR_CANCELLED
		})
	}()
	<-prompt
	err := g.restartAsAdmin(true, func(string, int) error {
		t.Error("concurrent request opened another UAC prompt")
		return nil
	})
	if err == nil || g.quitting.Load() {
		t.Error("an outstanding UAC request must keep the current instance alive")
	}
	close(cancel)
	if err := <-result; err == nil || g.quitting.Load() || g.restartingAsAdmin.Load() {
		t.Fatal("cancelled UAC left a pending restart", err)
	}
}
