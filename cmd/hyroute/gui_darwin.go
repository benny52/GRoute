//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/uirpc"
)

// GUI serves the windows connected to the service (hub_darwin.go): every
// exported method is callable from the page, as on Windows.
type GUI struct {
	ctl     *app.Controller
	dataDir string
	// binDir holds the service's own copies of HyRoute, hysteria and xray
	// (root's, installed with the service).
	binDir string
	life   context.Context
	win    *winHost
	core   *core.Manager

	dispatchOnce sync.Once
	dispatchFn   uirpc.Handler

	notice   string
	quitOnce sync.Once
	quitCh   chan struct{}
}

func (g *GUI) emitStatus() { g.win.notify("status") }

func (g *GUI) showWindow() { g.win.open("normal") }

func (g *GUI) quit() { g.quitOnce.Do(func() { close(g.quitCh) }) }

// The kill switch check at sign-in and hyroutectl's pipe are Windows'.
func (g *GUI) syncKillSwitchCheck() {}
func (g *GUI) applyCLI(string)      {}

var errMac = errors.New("на macOS этого пока нет")

// ---- start with the Mac: the service always runs (launchd) ----

func (g *GUI) Autostart() AutostartInfo {
	return AutostartInfo{Enabled: true, Allowed: true, Current: true, Command: filepath.Join(g.binDir, "HyRoute")}
}

func (g *GUI) SetAutostart(on bool) error {
	if !on {
		return errors.New("служба HyRoute запускается вместе с Mac всегда; подключение при запуске включается в «Настройках»")
	}
	return nil
}

func (g *GUI) BrowseExe() (string, error) {
	p, err := g.win.openFile(runtime.OpenDialogOptions{
		Title:                      "Выберите программу",
		DefaultDirectory:           "/Applications",
		TreatPackagesAsDirectories: false,
		Filters:                    []runtime.FileFilter{{DisplayName: "Программы", Pattern: "*.app"}},
	})
	if err != nil || p == "" {
		return p, err
	}
	return appExecutable(p), nil
}

// appExecutable is the program a .app bundle starts
// (Contents/Info.plist CFBundleExecutable): rules match its name.
func appExecutable(p string) string {
	if !strings.HasSuffix(p, ".app") {
		return p
	}
	out, err := exec.Command("/usr/bin/defaults", "read", filepath.Join(p, "Contents", "Info"), "CFBundleExecutable").Output()
	if name := strings.TrimSpace(string(out)); err == nil && name != "" && !strings.ContainsAny(name, "/\x00") {
		return filepath.Join(p, "Contents", "MacOS", name)
	}
	return p
}

func (g *GUI) OpenLogDir() error {
	dir := g.ctl.LogDir()
	if dir == "" {
		dir = filepath.Join(g.dataDir, "logs")
	}
	return errors.New("логи HyRoute лежат в " + dir + " (папка администратора: откройте её в Терминале через sudo)")
}

func (g *GUI) OpenDataDir() error {
	return errors.New("данные HyRoute лежат в " + g.dataDir + " (папка администратора)")
}

func (g *GUI) OpenSubscriptionSupport(id string) error {
	u, err := g.ctl.SupportLink(id)
	if err != nil {
		return err
	}
	return g.win.openPath(u)
}

func (g *GUI) ApplyAppUpdate() error {
	return errors.New("обновите HyRoute для macOS, скачав новую версию со страницы релизов")
}

func (g *GUI) System() SystemInfo {
	info := SystemInfo{Build: build, DataDir: g.dataDir, ProgramDir: g.binDir, RuntimeDir: g.binDir,
		Legacy: []string{}, Missing: []string{}, ProxyRules: []string{}, ProtectedLocation: true,
		Driver: "utun (встроен в macOS)", FirewallRuleOK: true}
	for _, f := range []string{"hysteria", "xray"} {
		if _, err := os.Stat(filepath.Join(g.binDir, f)); err != nil {
			info.Missing = append(info.Missing, f)
		}
	}
	info.Hysteria, info.HysteriaPath = g.coreVersion(), g.ctl.Base.HysteriaPath()
	return info
}

func (g *GUI) systemLines() []string {
	info := g.System()
	lines := []string{
		"macOS: " + macVersion(),
		"Служба: " + info.ProgramDir,
		"Данные: " + info.DataDir,
	}
	if len(info.Missing) > 0 {
		lines = append(lines, "Нет файлов: "+strings.Join(info.Missing, ", "))
	}
	return lines
}

func macVersion() string {
	out, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(out))
}

func (g *GUI) RemoveFirewallRule() error       { return errMac }
func (g *GUI) DeleteStaleDriverService() error { return errMac }
func (g *GUI) MoveToProgramFiles() error       { return errMac }
func (g *GUI) OpenServerPanel() error {
	return errors.New("панель серверов (hyroute-server) запускается на Windows или Linux")
}

// ---- Windows-only parts of «Настройки» ----

type BrowserExtView struct {
	On        bool   `json:"on"`
	Installed bool   `json:"installed"`
	Dir       string `json:"dir"`
	Version   string `json:"version"`
	Host      bool   `json:"host"`
	Browsers  []any  `json:"browsers"`
	Seen      int64  `json:"seen"`
}

func (g *GUI) BrowserExtInfo() BrowserExtView { return BrowserExtView{Browsers: []any{}} }
func (g *GUI) InstallBrowserExt() (BrowserExtView, error) {
	return g.BrowserExtInfo(), errMac
}
func (g *GUI) SetBrowserExtOn(bool) (BrowserExtView, error) { return g.BrowserExtInfo(), errMac }
func (g *GUI) RemoveBrowserExt() (BrowserExtView, error)    { return g.BrowserExtInfo(), errMac }
func (g *GUI) OpenBrowserExtensions(string) error           { return errMac }

type CLIInfo struct {
	Mode        string `json:"mode"`
	Listening   bool   `json:"listening"`
	Pipe        string `json:"pipe"`
	Exe         string `json:"exe"`
	Dir         string `json:"dir"`
	User        string `json:"user"`
	UserDiffers bool   `json:"userDiffers"`
	Error       string `json:"error,omitempty"`
	PrefsError  string `json:"prefsError,omitempty"`
}

func (g *GUI) CLIInfo() CLIInfo {
	return CLIInfo{Mode: "off", Error: "командная строка hyroutectl пока есть только на Windows"}
}
func (g *GUI) SetCLIMode(string) error { return errMac }

// ServiceVersion lets the window see whether the service is its own
// version (else it installs its copy).
func (g *GUI) ServiceVersion() string { return version + " " + build }

// Platform tells the page which system it runs on.
func (g *GUI) Platform() string { return "macos" }
