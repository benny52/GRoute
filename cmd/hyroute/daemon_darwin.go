//go:build darwin

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/killswitch"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/sysdns"
)

// runDaemon is the service: launchd starts it as root at boot
// (/Library/LaunchDaemons, install_darwin.go) and restarts it if it dies.
func runDaemon(verbose, stub bool) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "the HyRoute service runs as root (launchd starts it)")
		os.Exit(1)
	}
	// launchd gives a daemon no HOME: the data and the cores' folders are
	// root's (store.DefaultDir, core.DefaultDir).
	os.Setenv("HOME", "/var/root")
	// The kill switch lets this group's sockets through: the service's and
	// its cores' (they inherit it). Set before anything opens a socket.
	gid := killswitch.GroupID()
	if gid > 0 {
		if err := syscall.Setgid(gid); err != nil {
			fmt.Fprintln(os.Stderr, "HyRoute: group", killswitch.GroupName, "not set:", err)
			gid = 0
		}
	}
	exe, _ := os.Executable()
	binDir := filepath.Dir(exe)
	dataDir, err := store.DefaultDir() // root's: /var/root/Library/Application Support/HyRoute
	if err != nil {
		fatal(err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		fatal(err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		fatal(err)
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	hysteria.CleanRunDir(filepath.Join(dataDir, "run"), time.Minute)
	hysteriaPath := filepath.Join(binDir, "hysteria")
	xrayPath := filepath.Join(binDir, "xray")
	ctl := app.New(st, func(cfg session.Config) (app.Session, error) {
		return session.Start(cfg)
	}, session.Config{
		Dir:      binDir,
		Exe:      exe,
		RunDir:   filepath.Join(dataDir, "run"),
		Stub:     stub,
		Hysteria: func() string { return hysteriaPath },
		Xray:     func() string { return xrayPath },
	}, level)
	ctl.Log = slog.New(ctl.NewFileHandler(level, ctl.EngineWriter()))
	ctl.InstallOwnDial()
	ctl.LocalSuffixes = func() []string {
		i, _ := sysdns.Snapshot()
		return i.Suffixes
	}
	loadErr := ctl.Load()
	ctl.SetLogDir(filepath.Join(dataDir, "logs"))
	ctl.Log.Info("HyRoute service starting", "build", build, "version", version, "bin", binDir, "data", dataDir)
	if loadErr != nil {
		ctl.Log.Error("settings not loaded", "err", loadErr)
	}
	ctl.Version = version
	ctl.Device = deviceInfo
	coreMgr := &core.Manager{Dir: filepath.Join(dataDir, "core"), Bundled: hysteriaPath, Version: hysteria.ExeVersion}
	ctl.CoreVersion = func() string { return coreMgr.Info().Version }
	ctl.ListRunning = procinfo.ListRunning
	ctl.KillSwitch = &killswitch.Switch{GID: gid, StateDir: dataDir}
	ctl.InitKillSwitch()

	life, endLife := context.WithCancel(context.Background())
	defer endLife()
	gui := &GUI{ctl: ctl, dataDir: dataDir, binDir: binDir, life: life, core: coreMgr, quitCh: make(chan struct{})}
	gui.win = &winHost{g: gui}
	ctl.OnChange = gui.emitStatus
	ctl.OnSettings = func(rev uint64) { gui.win.notify("settings", rev) }
	ctl.OnGiveUp = gui.showWindow
	ctl.OnStartDecided = func() {}

	schedCtx, stopSched := context.WithCancel(context.Background())
	defer stopSched()
	go ctl.RunScheduler(schedCtx)
	go ctl.RunGeoUpdates(schedCtx)
	go ctl.RunStats(schedCtx)
	go ctl.RunNetModes(schedCtx, app.NetStartDecide)

	if err := gui.win.listen(); err != nil {
		fatal(fmt.Errorf("socket %s: %w", sockPath, err))
	}
	gui.applyCLI(gui.cliMode()) // hyroutectl
	go gui.syncBrowserExt()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
	case <-gui.quitCh:
	}
	ctl.Log.Info("HyRoute service stopping")
	endLife()
	gui.stopCLI()
	gui.win.close()
	ctl.StopNetModes()
	ctl.Shutdown()
	os.Remove(sockPath)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "HyRoute:", err)
	os.Exit(1)
}
