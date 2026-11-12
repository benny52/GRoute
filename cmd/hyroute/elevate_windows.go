package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

func canRestartAsAdmin() bool {
	return isPortableBuild() && !windows.GetCurrentProcessToken().IsElevated()
}

// RestartAsAdmin takes no path or arguments from the window. Only this
// backend can choose which executable to elevate and which PID it waits for.
func (g *GUI) RestartAsAdmin() error {
	return g.restartAsAdmin(canRestartAsAdmin(), launchAsAdmin)
}

func (g *GUI) restartAsAdmin(available bool, launch func(string, int) error) error {
	if !available {
		return errors.New("перезапуск доступен в GRoute Portable при запуске с обычными правами")
	}
	if g.quitting.Load() || !g.restartingAsAdmin.CompareAndSwap(false, true) {
		return errors.New("перезапуск GRoute уже начат")
	}
	exe, err := os.Executable()
	if err == nil {
		err = launch(exe, os.Getpid())
	}
	if err != nil {
		g.restartingAsAdmin.Store(false)
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errors.New("запуск от имени администратора отменён. GRoute продолжает работать с обычными правами")
		}
		return fmt.Errorf("не удалось запустить GRoute от имени администратора: %w", err)
	}
	g.quit()
	return nil
}

func launchAsAdmin(exe string, pid int) error {
	// All strings come from Windows or this process (no user input or NUL).
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	args, _ := windows.UTF16PtrFromString("--wait-pid=" + strconv.Itoa(pid))
	return windows.ShellExecute(0, verb, file, args, cwd, windows.SW_SHOWNORMAL)
}
