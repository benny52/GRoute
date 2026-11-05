//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/ctlserver"
	"github.com/lardan099/hyroute/internal/store"
)

// The command line (hyroutectl.exe): the control pipe served inside
// HyRoute, the run event that tells hyroutectl HyRoute is starting, and
// the «Командная строка» card's bindings. See internal/ctl.

// cliState is the command line's state; mu guards the fields and is never
// held while calling the controller or srv.Close.
type cliState struct {
	mu          sync.Mutex
	owner, self *windows.SID
	run         windows.Handle // run event (0 when it could not be created)
	runErr      error
	srv         *ctlserver.Server
	err         string // why the pipe is not up ("" = fine or off)
	retry       *time.Timer
	starting    bool // a Listen is under way
	off         bool // the mode last applied is «Выключено»: a Listen under way is dropped
	closed      bool // HyRoute exits
}

// cliRetry is how often a pipe that could not be created is tried again.
const cliRetry = 30 * time.Second

// initCLI runs right after the instance claim, before the controller
// exists: the owner (the interactive user of this session) and the run
// event, non-signalled («запускается») until startCLI.
func initCLI() *cliState {
	cs := &cliState{}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		cs.self, _ = u.User.Sid.Copy()
	}
	cs.owner = sessionUserSID()
	if cs.owner == nil {
		cs.owner = cs.self
	}
	if cs.owner == nil {
		cs.runErr = errors.New("no user SID")
		return cs
	}
	cs.run, cs.runErr = ctl.CreateRunEvent(ctl.RunEventName(cs.owner.String()), []*windows.SID{cs.owner, cs.self}, nil)
	return cs
}

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

// sessionUserSID is the interactive user of HyRoute's session: under
// over-the-shoulder UAC not the account HyRoute runs as. nil when unknown.
func sessionUserSID() *windows.SID {
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil {
		return nil
	}
	query := func(class uint32) string {
		var p *uint16
		var n uint32
		r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), uintptr(class), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n)))
		if r == 0 || p == nil {
			return ""
		}
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(p)))
		return windows.UTF16PtrToString(p)
	}
	const wtsUserName, wtsDomainName = 5, 7
	user, domain := query(wtsUserName), query(wtsDomainName)
	if user == "" {
		return nil
	}
	account := user
	if domain != "" {
		account = domain + `\` + user
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil
	}
	return sid
}

// allowClient: medium integrity or more, and the owner, HyRoute's own
// account, SYSTEM or an elevated administrator. The session is not checked:
// the same account over SSH or a scheduled task counts.
func allowClient(owner, self string) func(ctl.Identity) bool {
	return func(id ctl.Identity) bool {
		return id.IntegrityRID >= ctl.MediumRID && id.User != "" &&
			(id.User == owner || id.User == self || id.System || id.Elevated && id.Admin)
	}
}

// startCLI runs right before wails.Run (controller and prefs loaded): the
// pipe per the mode, then the run event says HyRoute has settled.
func (g *GUI) startCLI() {
	cs := g.cli
	if cs.runErr != nil {
		g.ctl.Log.Warn("command line: run event not created: hyroutectl cannot tell «starting» apart", "err", cs.runErr)
	}
	if _, err := g.ctl.CLIMode(); err != nil {
		g.ctl.Log.Warn("command line off: prefs.json did not load")
	}
	g.applyCLI(g.cliMode())
	if cs.run != 0 {
		windows.SetEvent(cs.run)
	}
}

// applyCLI makes the pipe follow mode (cliMode): "off" stops it, otherwise
// it is started unless it runs (full ↔ read ↔ browser needs no restart:
// the server reads the mode and the extension's switch per request).
func (g *GUI) applyCLI(mode string) {
	cs := g.cli
	if cs == nil || cs.owner == nil {
		return
	}
	cs.mu.Lock()
	if cs.closed {
		cs.mu.Unlock()
		return
	}
	cs.off = mode == "off"
	if mode == "off" {
		srv := cs.srv
		cs.srv, cs.err = nil, ""
		if cs.retry != nil {
			cs.retry.Stop()
			cs.retry = nil
		}
		cs.mu.Unlock()
		if srv != nil {
			srv.Close()
			g.ctl.Log.Info("command line: off")
		}
		return
	}
	if cs.srv != nil || cs.retry != nil || cs.starting {
		cs.mu.Unlock()
		return
	}
	cs.starting = true
	cs.mu.Unlock()

	owner, self := cs.owner.String(), cs.owner.String()
	if cs.self != nil {
		self = cs.self.String()
	}
	ln, err := ctl.Listen(ctl.ListenConfig{Name: ctl.PipeName(owner), Users: []*windows.SID{cs.owner, cs.self},
		Allow: allowClient(owner, self), MaxInstances: 8})
	cs.mu.Lock()
	cs.starting = false
	if cs.closed || cs.off {
		// Exiting, or switched off while Listen ran (that applyCLI saw no
		// server to stop).
		cs.mu.Unlock()
		if ln != nil {
			ln.Close()
		}
		return
	}
	if err != nil {
		if errors.Is(err, ctl.ErrNameTaken) {
			cs.err = "имя канала занято другой программой; HyRoute пробует снова каждые 30 секунд"
		} else {
			cs.err = "не удалось создать канал: " + err.Error()
		}
		cs.retry = time.AfterFunc(cliRetry, func() {
			cs.mu.Lock()
			cs.retry = nil
			cs.mu.Unlock()
			g.applyCLI(g.cliMode())
		})
		cs.mu.Unlock()
		g.ctl.Log.Warn("command line: pipe not created, retrying in 30 s", "err", err)
		g.emitStatus()
		return
	}
	srv := ctlserver.New(ctlBackend{g})
	cs.srv, cs.err = srv, ""
	cs.mu.Unlock()
	go srv.Serve(ln)
	g.ctl.Log.Info("command line: listening")
	g.emitStatus()
}

// stopCLI runs first in OnShutdown: from now on hyroutectl reports «не
// запущен».
func (g *GUI) stopCLI() {
	cs := g.cli
	if cs == nil {
		return
	}
	cs.mu.Lock()
	cs.closed = true
	if cs.retry != nil {
		cs.retry.Stop()
		cs.retry = nil
	}
	srv := cs.srv
	cs.srv = nil
	run := cs.run
	cs.run = 0
	cs.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
	if run != 0 {
		windows.CloseHandle(run)
	}
}

// CLIInfo is the «Командная строка» card.
type CLIInfo struct {
	Mode        string `json:"mode"` // effective: full | read | off
	Listening   bool   `json:"listening"`
	Pipe        string `json:"pipe"`
	Exe         string `json:"exe"` // hyroutectl.exe next to HyRoute.exe, "" when missing
	Dir         string `json:"dir"`
	User        string `json:"user"` // DOMAIN\name commands are accepted from
	UserDiffers bool   `json:"userDiffers"`
	Error       string `json:"error,omitempty"`
	PrefsError  string `json:"prefsError,omitempty"`
}

func (g *GUI) CLIInfo() CLIInfo {
	mode, perr := g.ctl.CLIMode()
	in := CLIInfo{Mode: mode, Dir: g.dllDir}
	if perr != nil {
		in.PrefsError = perr.Error()
	}
	if exe := filepath.Join(g.dllDir, "hyroutectl.exe"); fileExists(exe) {
		in.Exe = exe
	}
	cs := g.cli
	if cs == nil || cs.owner == nil {
		in.Error = "не удалось узнать учётную запись Windows"
		return in
	}
	cs.mu.Lock()
	in.Listening, in.Error = cs.srv != nil, cs.err
	cs.mu.Unlock()
	in.Pipe = ctl.PipeName(cs.owner.String())
	in.UserDiffers = cs.self != nil && !cs.owner.Equals(cs.self)
	if account, domain, _, err := cs.owner.LookupAccount(""); err == nil {
		in.User = account
		if domain != "" {
			in.User = domain + `\` + account
		}
	} else {
		in.User = cs.owner.String()
	}
	return in
}

// SetCLIMode is the card's select: full, read or off.
func (g *GUI) SetCLIMode(mode string) error {
	switch mode {
	case "full", "read", "off":
	default:
		return fmt.Errorf("неизвестный режим командной строки %q", mode)
	}
	if err := g.ctl.UpdatePrefs(func(p *store.Prefs) error {
		p.CLI = mode
		if mode == "read" {
			p.CLI = "" // the default: not written
		}
		return nil
	}); err != nil {
		return err
	}
	g.ctl.Log.Info("command line mode changed", "mode", mode)
	g.applyCLI(g.cliMode())
	return nil
}

// cliLine is the diagnostics line.
func (g *GUI) cliLine() string {
	in := g.CLIInfo()
	switch {
	case in.PrefsError != "":
		return "Командная строка: выключена: prefs.json не загружен"
	case in.Mode == "off":
		return "Командная строка: выключена"
	case in.Error != "":
		return "Командная строка: ошибка: " + in.Error
	case !in.Listening:
		return "Командная строка: канал не создан"
	case in.Mode == "full":
		return "Командная строка: полный доступ, канал работает"
	}
	return "Командная строка: только просмотр, канал работает"
}
