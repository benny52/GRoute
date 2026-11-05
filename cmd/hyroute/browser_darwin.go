//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/lardan099/hyroute/browser"
	"github.com/lardan099/hyroute/internal/ctl"
)

// The browser extension on macOS: the service writes the extension to a
// folder every user can read (the user loads it as unpacked) and the
// native messaging host manifest for hyroutectl into each browser's
// system-wide folder; the browser starts hyroutectl as the user, which
// talks to the service's command line socket.

type BrowserApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Exe    string `json:"exe"`
	Linked bool   `json:"linked"`
}

type BrowserExtView struct {
	On        bool         `json:"on"`
	Installed bool         `json:"installed"`
	Dir       string       `json:"dir"`
	Version   string       `json:"version"`
	Host      bool         `json:"host"`
	Browsers  []BrowserApp `json:"browsers"`
	Seen      int64        `json:"seen"`
}

// browserKind: a browser, its app and the system folders it reads native
// messaging hosts from.
type browserKind struct {
	id, name, page, app string
	dirs                []string
}

const chromeHosts = "/Library/Google/Chrome/NativeMessagingHosts"

var browserKinds = []browserKind{
	{"chrome", "Google Chrome", "chrome://extensions/", "/Applications/Google Chrome.app", []string{chromeHosts}},
	{"edge", "Microsoft Edge", "edge://extensions/", "/Applications/Microsoft Edge.app", []string{"/Library/Microsoft/Edge/NativeMessagingHosts"}},
	{"yandex", "Яндекс Браузер", "browser://extensions/", "/Applications/Yandex.app", []string{"/Library/Application Support/Yandex/YandexBrowser/NativeMessagingHosts", chromeHosts}},
	{"brave", "Brave", "brave://extensions/", "/Applications/Brave Browser.app", []string{"/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"}},
	{"opera", "Opera", "opera://extensions/", "/Applications/Opera.app", []string{chromeHosts}},
	{"vivaldi", "Vivaldi", "vivaldi://extensions/", "/Applications/Vivaldi.app", []string{"/Library/Application Support/Vivaldi/NativeMessagingHosts", chromeHosts}},
	{"chromium", "Chromium", "chrome://extensions/", "/Applications/Chromium.app", []string{"/Library/Application Support/Chromium/NativeMessagingHosts"}},
}

const browserBase = "/Library/Application Support/HyRoute"

func (g *GUI) browserDir() string { return filepath.Join(browserBase, browser.DirName) }
func (g *GUI) hostExe() string    { return filepath.Join(g.binDir, "hyroutectl") }

func hostManifest(dir string) string { return filepath.Join(dir, ctl.BrowserHost+".json") }

func manifestPoints(path, exe string) bool {
	b, err := os.ReadFile(path)
	return err == nil && string(b) == string(browser.HostManifest(exe))
}

func (g *GUI) BrowserExtInfo() BrowserExtView {
	v := BrowserExtView{On: g.ctl.BrowserOn(), Dir: g.browserDir(), Browsers: []BrowserApp{}}
	v.Version = browser.DiskVersion(v.Dir)
	v.Host = fileExists(g.hostExe())
	if t := g.ctl.BrowserSeen(); !t.IsZero() {
		v.Seen = t.Unix()
	}
	linkedAny := false
	for _, k := range browserKinds {
		b := BrowserApp{ID: k.id, Name: k.name}
		if fi, err := os.Stat(k.app); err == nil && fi.IsDir() {
			b.Exe = k.app
		}
		b.Linked = v.Version != ""
		for _, d := range k.dirs {
			b.Linked = b.Linked && manifestPoints(hostManifest(d), g.hostExe())
		}
		linkedAny = linkedAny || b.Linked
		if b.Exe != "" || b.Linked {
			v.Browsers = append(v.Browsers, b)
		}
	}
	v.Installed = v.Version != "" && linkedAny
	return v
}

func (g *GUI) InstallBrowserExt() (BrowserExtView, error) {
	if err := g.writeBrowserExt(true); err != nil {
		return g.BrowserExtInfo(), err
	}
	if err := g.ctl.SetBrowserOn(true); err != nil {
		return g.BrowserExtInfo(), err
	}
	g.applyCLI(g.cliMode())
	g.ctl.Log.Info("browser extension installed", "version", browser.Version())
	return g.BrowserExtInfo(), nil
}

// writeBrowserExt writes the extension and the host manifests (link: also
// for browsers not linked yet).
func (g *GUI) writeBrowserExt(link bool) error {
	if !fileExists(g.hostExe()) {
		return errors.New("hyroutectl не установлен: откройте новую версию HyRoute.app")
	}
	if err := os.MkdirAll(browserBase, 0o755); err != nil {
		return err
	}
	if err := browser.Write(g.browserDir()); err != nil {
		return errors.New("не удалось записать расширение: " + err.Error())
	}
	var errs []error
	done := map[string]bool{}
	for _, k := range browserKinds {
		for _, d := range k.dirs {
			if done[d] {
				continue
			}
			done[d] = true
			if !link && !fileExists(hostManifest(d)) {
				continue
			}
			if err := os.MkdirAll(d, 0o755); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := browser.WriteHostManifest(hostManifest(d), g.hostExe()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return errors.New("не удалось записать манифесты для браузеров: " + err.Error())
	}
	return nil
}

func (g *GUI) syncBrowserExt() {
	if !g.ctl.BrowserOn() || browser.DiskVersion(g.browserDir()) == "" {
		return
	}
	if err := g.writeBrowserExt(false); err != nil {
		g.ctl.Log.Warn("browser extension: not refreshed", "err", err)
	}
}

func (g *GUI) SetBrowserExtOn(on bool) (BrowserExtView, error) {
	if err := g.ctl.SetBrowserOn(on); err != nil {
		return g.BrowserExtInfo(), err
	}
	g.applyCLI(g.cliMode())
	return g.BrowserExtInfo(), nil
}

// RemoveBrowserExt removes the manifests that are HyRoute's and the
// extension's folder; the extension itself is removed in the browser.
func (g *GUI) RemoveBrowserExt() (BrowserExtView, error) {
	var errs []error
	if err := g.ctl.SetBrowserOn(false); err != nil {
		errs = append(errs, err)
	}
	g.applyCLI(g.cliMode())
	for _, k := range browserKinds {
		for _, d := range k.dirs {
			if p := hostManifest(d); manifestPoints(p, g.hostExe()) {
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := os.RemoveAll(g.browserDir()); err != nil {
		errs = append(errs, err)
	}
	return g.BrowserExtInfo(), errors.Join(errs...)
}

// OpenBrowserExtensions has the window (the user's session) open the
// browser's extensions page and show the extension's folder in Finder;
// the folder's path goes to the clipboard.
func (g *GUI) OpenBrowserExtensions(id string) error {
	for _, k := range browserKinds {
		if k.id != id {
			continue
		}
		g.CopyText(g.browserDir())
		g.win.call("reveal", g.browserDir())
		_, err := g.win.call("open.browser", k.app, k.page)
		return err
	}
	return errors.New("неизвестный браузер")
}

func (g *GUI) browserLine() string {
	v := g.BrowserExtInfo()
	var linked []string
	for _, b := range v.Browsers {
		if b.Linked {
			linked = append(linked, b.Name)
		}
	}
	switch {
	case !v.Installed && !v.On:
		return "Расширение для браузера: не установлено"
	case !v.On:
		return "Расширение для браузера: выключено"
	}
	return "Расширение для браузера: включено (" + strings.Join(linked, ", ") + ")"
}
