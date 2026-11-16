package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lardan099/hyroute/internal/core"
)

func (u *Updater) awgLibraryVersion(info core.Info) string {
	if u.AWGEngineVersion == nil {
		return ""
	}
	u.engineMu.Lock()
	defer u.engineMu.Unlock()
	if u.enginePath == info.Path && u.engineBuild == info.Version && (u.engineVersion != "" || time.Now().Before(u.engineRetry)) {
		return u.engineVersion
	}
	u.enginePath, u.engineBuild = info.Path, info.Version
	version, err := u.AWGEngineVersion(info.Path)
	u.engineVersion = version
	if err != nil {
		u.engineVersion = ""
		u.engineRetry = time.Now().Add(time.Minute)
	}
	return u.engineVersion
}

func (u *Updater) checkCore(ctx context.Context, manager *core.Manager, state *CoreState) {
	u.mu.Lock()
	revision, busy := state.revision, state.Busy
	u.mu.Unlock()
	if busy {
		return
	}
	offer, available, err := manager.Check(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	// A completed install or rollback wins over a check of the old version.
	if state.Busy || state.revision != revision {
		return
	}
	state.Error, state.Update = "", nil
	state.Unpublished = errors.Is(err, core.ErrNoAWGRelease)
	if err != nil && !state.Unpublished {
		state.Error = err.Error()
	}
	if available {
		state.Update = &offer
	}
}

func (c *Controller) InstallCore() error  { return c.changeCore("Hysteria", false) }
func (c *Controller) InstallXray() error  { return c.changeCore("Xray", false) }
func (c *Controller) InstallAWG() error   { return c.changeCore("AmneziaWG", false) }
func (c *Controller) RollbackCore() error { return c.changeCore("Hysteria", true) }
func (c *Controller) RollbackXray() error { return c.changeCore("Xray", true) }
func (c *Controller) RollbackAWG() error  { return c.changeCore("AmneziaWG", true) }

// Desktop bindings retain the individual methods; all three perform the same
// download, verification, activation and reconnect notification.
func (c *Controller) changeCore(name string, rollback bool) error {
	u := c.Updater
	if u == nil {
		return errors.New("обновление ядер недоступно")
	}
	var manager *core.Manager
	var state *CoreState
	switch name {
	case "Hysteria":
		manager, state = u.Core, &u.hysteria
	case "Xray":
		manager, state = u.Xray, &u.state.Xray
	case "AmneziaWG":
		manager, state = u.AWG, &u.state.AWG
	}
	if manager == nil {
		return fmt.Errorf("обновление %s недоступно", name)
	}
	if u.RequiresAdmin {
		return errors.New("для установки или отката ядра перезапустите GRoute от имени администратора")
	}
	u.mu.Lock()
	offer := state.Update
	if state.Busy {
		u.mu.Unlock()
		return fmt.Errorf("операция с ядром %s уже выполняется", name)
	}
	if !rollback && offer == nil {
		u.mu.Unlock()
		return fmt.Errorf("нет доступного обновления %s", name)
	}
	state.revision++
	state.Busy, state.Progress, state.Error = true, 0, ""
	u.mu.Unlock()
	c.changed()

	var err error
	if rollback {
		err = manager.Rollback()
	} else {
		err = manager.Install(context.Background(), *offer, func(done, total int64) {
			if total > 0 {
				u.mu.Lock()
				state.Progress = float64(done) / float64(total)
				u.mu.Unlock()
			}
		})
	}
	c.mu.Lock()
	session := c.sess
	u.mu.Lock()
	state.Busy = false
	if err != nil {
		state.Error = err.Error()
	} else {
		state.Update, state.session = nil, session
		state.Unpublished = false
	}
	u.mu.Unlock()
	c.mu.Unlock()
	if err == nil {
		c.Log.Info("core changed; new connections use the selected version", "core", name, "version", manager.Info().Version, "rollback", rollback)
		c.refreshKillSwitchApps()
	} else {
		c.Log.Error("core change failed", "core", name, "rollback", rollback, "err", err)
	}
	c.changed()
	return err
}
