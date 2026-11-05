//go:build darwin

package main

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/ctlserver"
	"github.com/lardan099/hyroute/internal/store"
)

// hyroutectl on macOS: the service serves the command line on a socket of
// its own (internal/ctl/pipe_darwin.go) per the «Командная строка» mode.
type cliState struct {
	mu  sync.Mutex
	srv *ctlserver.Server
	err string
}

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

// applyCLI makes the socket follow mode: "off" closes it, anything else
// keeps one open (the server reads the mode per request).
func (g *GUI) applyCLI(mode string) {
	cs := &g.cli
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if mode == "off" {
		if cs.srv != nil {
			cs.srv.Close()
			cs.srv = nil
			g.ctl.Log.Info("command line: off")
		}
		cs.err = ""
		return
	}
	if cs.srv != nil {
		return
	}
	ln, err := ctl.ListenUnix(ctl.SockPath)
	if err != nil {
		cs.err = "не удалось создать сокет: " + err.Error()
		g.ctl.Log.Warn("command line: socket not created", "err", err)
		return
	}
	cs.srv, cs.err = ctlserver.New(ctlBackend{g}), ""
	go cs.srv.Serve(ln)
	g.ctl.Log.Info("command line: listening", "socket", ctl.SockPath)
}

func (g *GUI) stopCLI() { g.applyCLI("off") }

func (g *GUI) CLIInfo() CLIInfo {
	mode, perr := g.ctl.CLIMode()
	in := CLIInfo{Mode: mode, Dir: g.binDir, Pipe: ctl.SockPath, User: "администраторы этого Mac"}
	if perr != nil {
		in.PrefsError = perr.Error()
	}
	if exe := filepath.Join(g.binDir, "hyroutectl"); fileExists(exe) {
		in.Exe = hyroutectlLink
	}
	g.cli.mu.Lock()
	in.Listening, in.Error = g.cli.srv != nil, g.cli.err
	g.cli.mu.Unlock()
	return in
}

// hyroutectlLink is where the install puts hyroutectl on the PATH.
const hyroutectlLink = "/usr/local/bin/hyroutectl"

func (g *GUI) SetCLIMode(mode string) error {
	switch mode {
	case "full", "read", "off":
	default:
		return fmt.Errorf("неизвестный режим командной строки %q", mode)
	}
	if err := g.ctl.UpdatePrefs(func(p *store.Prefs) error {
		p.CLI = mode
		if mode == "read" {
			p.CLI = ""
		}
		return nil
	}); err != nil {
		return err
	}
	g.applyCLI(g.cliMode())
	return nil
}

func (g *GUI) cliLine() string {
	in := g.CLIInfo()
	switch {
	case in.Mode == "off":
		return "Командная строка: выключена"
	case in.Error != "":
		return "Командная строка: ошибка: " + in.Error
	case in.Mode == "full":
		return "Командная строка: полный доступ"
	}
	return "Командная строка: только просмотр"
}
