package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/update"
)

// Updater wires the release checks into the controller.
type Updater struct {
	// CoresOnly disables client updates while allowing independent core releases.
	CoresOnly bool
	// RequiresAdmin is set by the ordinary Windows portable process. The
	// elevated instance writes the common, administrator-owned core store.
	RequiresAdmin bool
	// Repo is HyRoute's GitHub repository ("owner/name"); empty disables
	// self-update.
	Repo string
	// Dir is the protected staging directory for HyRoute packages.
	Dir  string
	Core *core.Manager
	// Xray is the core of VLESS servers (nil = no Xray updates).
	Xray             *core.Manager
	AWG              *core.Manager
	AWGEngineVersion func(string) (string, error)
	Client           *release.Client

	mu                                     sync.Mutex
	state                                  UpdatesState
	hysteria                               CoreState // projected onto the legacy Core* fields for the UI
	engineMu                               sync.Mutex
	enginePath, engineBuild, engineVersion string
	engineRetry                            time.Time
}

// UpdatesState is shown in the UI.
type UpdatesState struct {
	Current  string    `json:"current"`
	Dev      bool      `json:"dev"` // build without a release tag
	Repo     string    `json:"repo"`
	Checked  time.Time `json:"checked"`
	Checking bool      `json:"checking"`

	App         *update.Available `json:"app"`
	AppError    string            `json:"appError"`
	AppStage    string            `json:"appStage"` // "" | downloading | ready
	AppProgress float64           `json:"appProgress"`
	AppSkipped  bool              `json:"appSkipped"` // user chose "Позже" for this version

	Core            core.Info    `json:"core"`
	CoreUpdate      *core.Update `json:"coreUpdate"`
	CoreError       string       `json:"coreError"`
	CoreBusy        bool         `json:"coreBusy"`
	CoreProgress    float64      `json:"coreProgress"`
	CoreNeedsReconn bool         `json:"coreNeedsReconnect"`

	// Xray, the core of VLESS servers: the same as the Core fields.
	Xray CoreState `json:"xray"`
	AWG  CoreState `json:"awg"`

	staging string
}

// CoreState is the release check and installation state for one engine.
type CoreState struct {
	EngineVersion   string `json:"engineVersion,omitempty"`
	UpstreamVersion string `json:"upstreamVersion,omitempty"`
	UpstreamError   string `json:"upstreamError,omitempty"`
	UpstreamNewer   bool   `json:"upstreamNewer,omitempty"`
	revision        uint64
	Unpublished     bool `json:"unpublished,omitempty"`
	session         Session
	Info            core.Info    `json:"info"`
	Update          *core.Update `json:"update"`
	Error           string       `json:"error"`
	Busy            bool         `json:"busy"`
	Progress        float64      `json:"progress"`
	NeedsReconnect  bool         `json:"needsReconnect"`
}

// IsDev reports builds that are not a release (no "vX.Y.Z" tag).
func IsDev(v string) bool {
	p, err := release.Parse(v)
	return err != nil || strings.Contains(p.Pre, "dev") || strings.Contains(p.Pre, "-g")
}

func (c *Controller) Updates() UpdatesState {
	u := c.Updater
	if u == nil {
		return UpdatesState{Current: c.Version, Dev: IsDev(c.Version)}
	}
	c.mu.Lock()
	session := c.sess
	u.mu.Lock()
	for _, cs := range []*CoreState{&u.hysteria, &u.state.Xray, &u.state.AWG} {
		if cs.session != session {
			cs.session = nil
		}
		cs.NeedsReconnect = cs.session != nil
	}
	st := u.state
	hy := u.hysteria
	u.mu.Unlock()
	c.mu.Unlock()
	st.Current, st.Dev, st.Repo = c.Version, IsDev(c.Version), u.Repo
	st.CoreUpdate, st.CoreError, st.CoreBusy = hy.Update, hy.Error, hy.Busy
	st.CoreProgress, st.CoreNeedsReconn = hy.Progress, hy.NeedsReconnect
	if u.Core != nil {
		st.Core = u.Core.Info()
	}
	if u.Xray != nil {
		st.Xray.Info = u.Xray.Info()
	}
	if u.AWG != nil {
		st.AWG.Info = u.AWG.Info()
		st.AWG.EngineVersion = u.awgLibraryVersion(st.AWG.Info)
		st.AWG.UpstreamNewer = st.AWG.EngineVersion != "" && release.Compare(st.AWG.UpstreamVersion, st.AWG.EngineVersion) > 0
	}
	if st.App != nil {
		st.AppSkipped = c.Prefs().SkipVersion == st.App.Version
	}
	return st
}

func (u *Updater) set(f func(*UpdatesState)) {
	u.mu.Lock()
	f(&u.state)
	u.mu.Unlock()
}

// CheckUpdates queries each configured engine independently.
func (c *Controller) CheckUpdates() UpdatesState {
	u := c.Updater
	if u == nil {
		return c.Updates()
	}
	u.mu.Lock()
	if u.state.Checking {
		u.mu.Unlock()
		return c.Updates()
	}
	u.state.Checking = true
	u.mu.Unlock()
	c.changed()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	if u.AWG != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			version, err := u.Client.LatestStableTag(ctx, "amnezia-vpn/amneziawg-go", 3)
			u.set(func(s *UpdatesState) {
				s.AWG.UpstreamVersion, s.AWG.UpstreamError = version, ""
				if err != nil {
					s.AWG.UpstreamError = err.Error()
				}
			})
		}()
	}
	for _, item := range []struct {
		manager *core.Manager
		state   *CoreState
	}{{u.Core, &u.hysteria}, {u.Xray, &u.state.Xray}, {u.AWG, &u.state.AWG}} {
		if item.manager != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				u.checkCore(ctx, item.manager, item.state)
			}()
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if u.CoresOnly {
			return
		}
		if u.Repo == "" {
			u.set(func(s *UpdatesState) {
				s.AppError = "в этой сборке не задан репозиторий обновлений"
			})
			return
		}
		a, ok, err := update.Check(ctx, u.Client, u.Repo, c.Version, c.channel())
		u.set(func(s *UpdatesState) {
			s.AppError = ""
			if err != nil {
				s.AppError = err.Error()
			}
			// A download under way finishes (DownloadAppUpdate drops
			// it if the offer changed meanwhile): no second one starts.
			busy := s.AppStage == "downloading"
			if ok {
				if (s.App == nil || s.App.Version != a.Version) && !busy {
					s.AppStage, s.AppProgress = "", 0
				}
				s.App = &a
			} else if err == nil {
				s.App = nil
				if !busy {
					s.AppStage = ""
				}
			}
		})
		if ok {
			c.Log.Info("HyRoute update available", "current", c.Version, "new", a.Version)
		}
	}()
	wg.Wait()
	u.set(func(s *UpdatesState) { s.Checking, s.Checked = false, time.Now() })
	c.changed()
	return c.Updates()
}

func (c *Controller) channel() string {
	if ch := c.Prefs().UpdateChannel; ch != "" {
		return ch
	}
	return "stable"
}

// refreshKillSwitchApps: the block lets HyRoute's programs through, and a
// core update or rollback moves hysteria.exe. An installed block (armed or
// blocking) lets the new core through now, not only after the next Arm:
// a server check or a new profile starts it at once. The DNS servers the
// block lets Windows reach are renewed too (see InitKillSwitch and
// startLocked).
func (c *Controller) refreshKillSwitchApps() {
	ks, ok := c.KillSwitch.(interface{ RefreshApps() error })
	if !ok {
		return
	}
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	if !c.ks.blocks {
		return
	}
	if err := ks.RefreshApps(); err != nil {
		c.Log.Error("kill switch: exceptions not renewed (HyRoute, Hysteria, DNS servers)", "err", err)
	}
}

// DownloadAppUpdate downloads and verifies the offered HyRoute package.
func (c *Controller) DownloadAppUpdate() error {
	u := c.Updater
	if u == nil || u.CoresOnly {
		return errors.New("обновление недоступно")
	}
	u.mu.Lock()
	a := u.state.App
	if a == nil || u.state.AppStage == "downloading" {
		u.mu.Unlock()
		return errors.New("нет доступного обновления")
	}
	u.state.AppStage, u.state.AppProgress, u.state.AppError = "downloading", 0, ""
	u.mu.Unlock()
	c.changed()
	if err := core.ProtectDir(u.Dir); err != nil {
		u.set(func(s *UpdatesState) { s.AppStage, s.AppError = "", err.Error() })
		c.changed()
		return err
	}
	// No overall limit, as for the core (InstallCore).
	dir, err := update.Stage(context.Background(), u.Client, *a, u.Dir, func(done, total int64) {
		if total > 0 {
			u.set(func(s *UpdatesState) { s.AppProgress = float64(done) / float64(total) })
		}
	})
	u.set(func(s *UpdatesState) {
		if err == nil && (s.App == nil || s.App.Version != a.Version) {
			// A check meanwhile found another version (or none): this
			// package is not what the UI offers.
			err = fmt.Errorf("пока шла загрузка %s, предложение обновления изменилось: повторите", a.Version)
		}
		if err != nil {
			s.AppStage, s.AppProgress, s.AppError = "", 0, err.Error()
			return
		}
		s.AppStage, s.staging = "ready", dir
	})
	if err != nil {
		c.Log.Error("HyRoute update download failed", "err", err)
	} else {
		c.Log.Info("HyRoute update downloaded and verified", "version", a.Version)
	}
	c.changed()
	return err
}

// ReadyUpdate returns the verified staging directory and its version.
func (c *Controller) ReadyUpdate() (dir, version string, err error) {
	u := c.Updater
	if u == nil || u.CoresOnly {
		return "", "", errors.New("обновление недоступно")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state.AppStage != "ready" || u.state.App == nil {
		return "", "", errors.New("обновление ещё не скачано")
	}
	m, err := update.Verify(u.state.staging)
	if err != nil {
		u.state.AppStage = ""
		return "", "", fmt.Errorf("скачанное обновление повреждено: %w", err)
	}
	if release.Compare(m.Version, u.state.App.Version) != 0 {
		u.state.AppStage = ""
		return "", "", fmt.Errorf("скачана версия %s, а предлагается %s: скачайте заново", m.Version, u.state.App.Version)
	}
	return u.state.staging, u.state.App.Version, nil
}

// SkipAppVersion is "Позже": no startup prompt for this version.
func (c *Controller) SkipAppVersion(v string) error {
	return c.UpdatePrefs(func(p *store.Prefs) error { p.SkipVersion = v; return nil })
}

// RunUpdateChecks checks at start (after a delay) and every 12 hours when
// automatic checks are on. Development builds only check on request.
func (c *Controller) RunUpdateChecks(ctx context.Context) {
	auto := func() bool {
		m := c.Prefs().UpdateCheck
		return m == "auto" || (m == "" && !IsDev(c.Version))
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}
	if auto() {
		c.CheckUpdates()
	}
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if auto() {
				c.CheckUpdates()
			}
		}
	}
}
