package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/zapret"
)

// «Обход DPI» (zapret2): winws2 next to HyRoute's engine processes the
// traffic HyRoute sends direct (internal/zapret). The user ticks services
// (YouTube, Discord, own sites); HyRoute keeps rules «Обход DPI: …» at the
// top of the active rule profile so their traffic goes direct and not
// through a tunnel, builds winws2's command line, keeps winws2 running and,
// on «Подобрать», finds a method that works on this network. winws2 runs
// whenever the bypass is on, connected or not: the bypass works without a
// VPN too.

// zapretState is the Controller's part (zapretMu unless noted).
type zapretState struct {
	zapretMu   sync.Mutex // serializes apply and pick; taken before c.mu
	zapretCfg  zapret.Settings
	zapretErr  error // zapret.json did not load: nothing is written
	zapretRun  *zapret.Runner
	zapretDir  string // winws2's folder once staged
	zapretPrep string // why it could not be staged
	zapretArgs []string
	zapretKey  string             // the network zapretArgs were built for
	zapretNet  string             // its name, for the page
	zapretStop context.CancelFunc // ends zapretWatch
	zapretPick *ZapretPickView
	pickCancel context.CancelFunc
	// pickMu guards zapretPick, pickCancel, zapretBusy and zapretShown
	// (read by ZapretInfo while an apply or a pick holds zapretMu).
	pickMu      sync.Mutex
	zapretBusy  string      // «Скачиваю zapret2…» while staging
	zapretShown *ZapretView // the last view built with zapretMu held
}

// ZapretRulePrefix starts the name of a rule the bypass keeps.
const ZapretRulePrefix = "Обход DPI: "

// Test hooks.
var (
	zapretSettle    = 1500 * time.Millisecond // winws2 opens WinDivert and reads its lists
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		return (&zapret.Prober{Slot: slot}).Check(ctx, urls)
	}
	zapretSpawn func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) // nil = winws2
)

// ZapretView is the «Обход DPI» page.
type ZapretView struct {
	// Available: this build can run the bypass (Windows).
	Available bool            `json:"available"`
	Settings  zapret.Settings `json:"settings"`
	Status    zapret.Status   `json:"status"`
	// Preparing: winws2 is being downloaded; PrepareError: why it could not.
	PrepareError string `json:"prepareError,omitempty"`
	LoadError    string `json:"loadError,omitempty"`
	// Network: the network the picked methods apply to ("" = unknown).
	Network     string             `json:"network"`
	Targets     []ZapretTargetView `json:"targets"`
	Methods     []ZapretMethodView `json:"methods"`
	Pick        *ZapretPickView    `json:"pick,omitempty"`
	CommandLine string             `json:"commandLine,omitempty"`
	// Busy: what takes time now («Скачиваю zapret2…»).
	Busy string `json:"busy,omitempty"`
	// HasServer: there is a main server to send a target through.
	HasServer bool `json:"hasServer"`
}

// ZapretDiag is how a target is blocked.
type ZapretDiag struct {
	Kind   zapret.Kind `json:"kind"`
	Text   string      `json:"text"`   // the kind, for the user
	Detail string      `json:"detail"` // the address and what happened
	// Bypass: a method can open it; otherwise only the VPN can.
	Bypass bool `json:"bypass"`
}

func methodIndex(id string) int {
	return slices.IndexFunc(zapret.Methods, func(m zapret.Method) bool { return m.ID == id })
}

// ZapretTargetView is one service of the page.
type ZapretTargetView struct {
	Target zapret.Target `json:"target"`
	Name   string        `json:"name"`
	On     bool          `json:"on"`
	// Fixed: the method the user chose ("" = automatic).
	Fixed string `json:"fixed,omitempty"`
	// Picked: what auto-pick found on this network: a method ID, "none"
	// (not blocked) or "" (not picked, or nothing worked).
	Picked   string `json:"picked,omitempty"`
	PickedAt int64  `json:"pickedAt,omitempty"` // Unix ms
	// Using: what runs now, in words.
	Using string `json:"using"`
}

type ZapretMethodView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ZapretPickView is an auto-pick under way or just done.
type ZapretPickView struct {
	Running bool                     `json:"running"`
	Step    string                   `json:"step"`
	Done    int                      `json:"done"`
	Total   int                      `json:"total"`
	Results map[zapret.Target]string `json:"results"` // a method ID, "none", or "" (none worked)
	// Working: every method that opened the target, fastest first.
	Working map[zapret.Target][]string `json:"working,omitempty"`
	// Diagnosis: how a target is blocked without a bypass.
	Diagnosis map[zapret.Target]ZapretDiag `json:"diagnosis,omitempty"`
	Error     string                       `json:"error,omitempty"`
}

// ZapretInput is what the page saves.
type ZapretInput struct {
	Enabled bool                     `json:"enabled"`
	Targets []zapret.Target          `json:"targets"`
	Sites   []string                 `json:"sites"`
	Methods map[zapret.Target]string `json:"methods"`
}

// loadZapret reads zapret.json (Load).
func (c *Controller) loadZapret() {
	if c.Store == nil {
		return
	}
	cfg, err := c.Store.LoadZapret()
	c.zapretMu.Lock()
	c.zapretCfg, c.zapretErr = cfg, err
	c.zapretMu.Unlock()
	if err != nil {
		c.Log.Error("zapret.json not loaded: the DPI bypass is off", "err", err)
	}
}

// StartZapret starts the bypass when it is on (main, once ZapretPrepare
// is set). It returns at once.
func (c *Controller) StartZapret() {
	go c.zapretApply()
}

func (c *Controller) zapretRunner() *zapret.Runner {
	if c.zapretRun == nil {
		c.zapretRun = &zapret.Runner{Log: c.Log, OnChange: c.changed, Spawn: zapretSpawn}
	}
	return c.zapretRun
}

// zapretReady stages winws2 (once) and returns its folder.
func (c *Controller) zapretReady(ctx context.Context) (string, error) {
	if c.zapretDir != "" {
		return c.zapretDir, nil
	}
	if c.ZapretPrepare == nil {
		return "", errors.New("обход DPI работает только на Windows")
	}
	c.setZapretBusy("Скачиваю zapret2 и проверяю его файлы…")
	dir, err := c.ZapretPrepare(ctx)
	c.setZapretBusy("")
	if err != nil {
		c.zapretPrep = "Не удалось скачать zapret2: " + err.Error()
		c.changed()
		return "", errors.New(c.zapretPrep)
	}
	c.zapretDir, c.zapretPrep = dir, ""
	return dir, nil
}

func (c *Controller) setZapretBusy(s string) {
	c.pickMu.Lock()
	c.zapretBusy = s
	c.pickMu.Unlock()
	c.changed()
}

// zapretNetKey is the network auto-pick results belong to, and its name.
func (c *Controller) zapretNetKey() (key, name string) {
	if c.NetWatcher == nil {
		return "", ""
	}
	snap, err := c.NetWatcher.Snapshot(false)
	if err != nil || snap.Active == nil {
		return "", ""
	}
	a := snap.Active
	name = a.Name
	switch {
	case a.Identified && a.ID != "":
		return "id:" + strings.ToUpper(a.ID), name
	case a.GatewayMAC != "":
		return "gw:" + a.GatewayMAC, name
	}
	return "", name
}

// zapretServers are the addresses of HyRoute's servers now: every profile
// of winws2 skips them.
func (c *Controller) zapretServers() []netip.Addr {
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	if s == nil {
		return nil
	}
	var out []netip.Addr
	for _, t := range s.Tunnels() {
		for _, ip := range t.ServerIPs {
			if a, err := netip.ParseAddr(ip); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// zapretServersChanged rewrites the server list while winws2 runs (it
// rereads a list file when it changes).
func (c *Controller) zapretServersChanged() {
	if c.ZapretLists == "" {
		return
	}
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	if c.zapretArgs == nil {
		return
	}
	if err := zapret.WriteLists(c.ZapretLists, c.zapretCfg.Sites, c.zapretServers()); err != nil {
		c.Log.Warn("zapret: lists not written", "err", err)
	}
}

// zapretApply makes winws2 and the rules follow the settings.
func (c *Controller) zapretApply() {
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	c.zapretApplyLocked()
}

func (c *Controller) zapretApplyLocked() {
	cfg := c.zapretCfg
	run := c.zapretRunner()
	c.syncZapretRules(cfg)
	defer c.zapretWatchLocked(cfg)
	if c.zapretErr != nil || !cfg.Enabled || len(cfg.Targets) == 0 || c.ZapretPrepare == nil || c.ZapretLists == "" {
		c.zapretArgs = nil
		run.Stop()
		return
	}
	// The network is read only when a pick made it matter.
	key, name := "", ""
	if len(cfg.Picked) > 0 {
		key, name = c.zapretNetKey()
	}
	c.zapretKey, c.zapretNet = key, name
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir, err := c.zapretReady(ctx)
	if err != nil {
		run.Stop()
		return
	}
	plans := map[zapret.Target]zapret.Plan{}
	for _, t := range cfg.Targets {
		if p, ok := cfg.PlanFor(t, key); ok {
			plans[t] = p
		}
	}
	if len(plans) == 0 {
		// Nothing is blocked here: no winws2 at all.
		c.zapretArgs = nil
		run.Stop()
		return
	}
	if err := zapret.WriteLists(c.ZapretLists, cfg.Sites, c.zapretServers()); err != nil {
		c.Log.Error("zapret: lists not written", "err", err)
		run.Stop()
		return
	}
	args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: c.ZapretLists, Plans: plans, Filter: zapret.ProbeExclude()})
	if err != nil {
		c.Log.Error("zapret: command line not built", "err", err)
		run.Stop()
		return
	}
	if slices.Equal(args, c.zapretArgs) && run.Status().State != zapret.Off {
		return
	}
	c.zapretArgs = args
	run.Exe = filepath.Join(dir, "winws2.exe")
	c.Log.Info("zapret: winws2 starting", "targets", len(plans))
	run.Start(args)
}

// zapretNetDependent: what winws2 does depends on the network (a method
// was picked on some network for a target the user left automatic).
func zapretNetDependent(cfg zapret.Settings) bool {
	if !cfg.Enabled || len(cfg.Picked) == 0 {
		return false
	}
	for _, t := range cfg.Targets {
		if cfg.Methods[t] == "" {
			return true
		}
	}
	return false
}

// zapretWatchLocked runs zapretWatch while the network matters, so the
// network is not read when it does not.
func (c *Controller) zapretWatchLocked(cfg zapret.Settings) {
	want := c.zapretErr == nil && c.NetWatcher != nil && zapretNetDependent(cfg)
	if want == (c.zapretStop != nil) {
		return
	}
	if !want {
		c.zapretStop()
		c.zapretStop = nil
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.zapretStop = cancel
	go c.zapretWatch(ctx)
}

// Test hooks: how long a burst of network events settles, and the poll.
var (
	zapretNetQuiet = 4 * time.Second
	zapretNetPoll  = time.Minute
)

// zapretWatch re-applies when the network changes: the methods picked on
// one network are not the ones of another (and on one where nothing is
// blocked winws2 does not run at all).
func (c *Controller) zapretWatch(ctx context.Context) {
	events, err := c.NetWatcher.Watch(ctx)
	if err != nil {
		events = nil // the poll alone
	}
	poll := time.NewTicker(zapretNetPoll)
	defer poll.Stop()
	var settle <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
			if settle == nil {
				settle = time.After(zapretNetQuiet)
			}
			continue
		case <-settle:
			settle = nil
		case <-poll.C:
		}
		key, _ := c.zapretNetKey()
		c.zapretMu.Lock()
		if ctx.Err() == nil && key != c.zapretKey {
			c.Log.Info("zapret: network changed, rebuilding")
			c.zapretApplyLocked()
		}
		c.zapretMu.Unlock()
	}
}

// zapretRules are the rules the bypass keeps for cfg, top first.
func zapretRules(cfg zapret.Settings) []rules.Rule {
	if !cfg.Enabled {
		return nil
	}
	var out []rules.Rule
	for _, t := range zapret.Targets {
		if !cfg.On(t) {
			continue
		}
		// Direct, through winws2; through the main server where the user
		// chose the VPN for it (blocked by address: no bypass opens that).
		act := rules.Direct
		if cfg.Methods[t] == zapret.VPN {
			act = rules.Tunnel
		}
		doms := zapret.Domains(t, cfg.Sites)
		if len(doms) > 0 {
			out = append(out, rules.Rule{Name: ZapretRulePrefix + zapret.TargetName(t), Domains: slices.Clone(doms), Action: act})
		}
		if t == zapret.Discord {
			// Voice goes to addresses without names, from the program.
			out = append(out, rules.Rule{Name: ZapretRulePrefix + "Discord (голос)",
				Apps:     []rules.AppMatch{{Pattern: "Discord.exe", InheritChildren: true}},
				Protocol: "udp", Ports: rules.PortList{"19294-19344", "50000-50100"}, Action: act})
		}
	}
	return out
}

func isZapretRule(r rules.Rule) bool { return strings.HasPrefix(r.Name, ZapretRulePrefix) }

// sameZapretRule: r is the kept rule w (its ID and switch aside).
func sameZapretRule(r, w rules.Rule) bool {
	return r.Name == w.Name && slices.Equal(r.Domains, w.Domains) && r.Action == w.Action && r.Protocol == w.Protocol &&
		slices.Equal(r.Ports, w.Ports) && len(r.Apps) == len(w.Apps)
}

// syncZapretRules keeps the rules «Обход DPI: …» at the top of the active
// rule profile, as the settings want them. A rule the user switched off
// stays off.
func (c *Controller) syncZapretRules(cfg zapret.Settings) {
	want := zapretRules(cfg)
	_, err := c.editRules(func(rc *rules.Config) (bool, error) {
		var have []rules.Rule
		for _, r := range rc.Rules {
			if isZapretRule(r) {
				have = append(have, r)
			}
		}
		same := len(have) == len(want)
		for i := 0; same && i < len(want); i++ {
			same = sameZapretRule(have[i], want[i]) && rc.Rules[i].Name == want[i].Name
		}
		if same {
			return false, nil
		}
		off := map[string]bool{}
		for _, r := range have {
			if !r.On() {
				off[r.Name] = true
			}
		}
		rest := slices.DeleteFunc(slices.Clone(rc.Rules), isZapretRule)
		top := make([]rules.Rule, len(want))
		for i, w := range want {
			w.ID = newID()
			if off[w.Name] {
				f := false
				w.Enabled = &f
			}
			top[i] = w
		}
		rc.Rules = append(top, rest...)
		return true, nil
	})
	if err != nil {
		c.Log.Warn("zapret: rules not updated", "err", err)
	}
}

// pickState copies what moves under pickMu.
func (c *Controller) pickState() (pick *ZapretPickView, busy string, shown *ZapretView) {
	c.pickMu.Lock()
	defer c.pickMu.Unlock()
	if c.zapretPick != nil {
		cp := *c.zapretPick
		cp.Results = cloneMap(c.zapretPick.Results)
		cp.Diagnosis = cloneMap(c.zapretPick.Diagnosis)
		cp.Working = cloneMap(c.zapretPick.Working)
		pick = &cp
	}
	return pick, c.zapretBusy, c.zapretShown
}

// ZapretInfo is the page's view.
func (c *Controller) ZapretInfo() ZapretView {
	pick, busy, shown := c.pickState()
	if !c.zapretMu.TryLock() {
		// An apply or a pick holds the settings: their last view, with
		// what moves now.
		v := ZapretView{Available: c.ZapretPrepare != nil}
		if shown != nil {
			v = *shown
		}
		v.Pick, v.Busy, v.Status = pick, busy, c.zapretRunner().Status()
		return v
	}
	defer c.zapretMu.Unlock()
	return c.zapretInfoLocked(pick, busy)
}

// zapretInfoLocked builds the view (zapretMu held).
func (c *Controller) zapretInfoLocked(pick *ZapretPickView, busy string) ZapretView {
	v := ZapretView{Available: c.ZapretPrepare != nil, Pick: pick, Busy: busy}
	c.mu.Lock()
	v.HasServer = c.mainTargetLocked() != ""
	c.mu.Unlock()
	for _, m := range zapret.Methods {
		v.Methods = append(v.Methods, ZapretMethodView{ID: m.ID, Name: m.Name})
	}
	key, name := c.zapretKey, c.zapretNet // as of the last apply: the page does not read the network
	v.Network = name
	cfg := c.zapretCfg
	v.Settings = cfg
	if v.Settings.Targets == nil {
		v.Settings.Targets = []zapret.Target{}
	}
	if c.zapretErr != nil {
		v.LoadError = c.zapretErr.Error()
	}
	v.PrepareError = c.zapretPrep
	v.Status = c.zapretRunner().Status()
	if c.zapretArgs != nil {
		v.CommandLine = zapret.CommandLine(c.zapretArgs)
	}
	pk := cfg.Picked[key]
	for _, t := range zapret.Targets {
		tv := ZapretTargetView{Target: t, Name: zapret.TargetName(t), On: cfg.On(t), Fixed: cfg.Methods[t], Picked: pk.Methods[t]}
		if !pk.At.IsZero() && tv.Picked != "" {
			tv.PickedAt = pk.At.UnixMilli()
		}
		switch p, ok := cfg.PlanFor(t, key); {
		case !tv.On:
		case cfg.Methods[t] == zapret.VPN:
			tv.Using = "через VPN, без обхода"
			if !v.HasServer {
				tv.Using = "через VPN — но сервер не выбран: добавьте сервер"
			}
		case !ok:
			tv.Using = "не нужен: здесь не блокируется"
		case p.Circular:
			tv.Using = "автоматически, начиная с «" + zapret.MethodName(p.Methods[0]) + "»"
		default:
			tv.Using = zapret.MethodName(p.Methods[0])
		}
		v.Targets = append(v.Targets, tv)
	}
	c.pickMu.Lock()
	cp := v
	c.zapretShown = &cp
	c.pickMu.Unlock()
	return v
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SaveZapret saves the page and applies it.
func (c *Controller) SaveZapret(in ZapretInput) error {
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	if c.zapretErr != nil {
		return fmt.Errorf("zapret.json не загружен, изменения не сохраняются: %v", c.zapretErr)
	}
	next := c.zapretCfg
	next.Enabled, next.Targets, next.Sites, next.Methods = in.Enabled, in.Targets, in.Sites, in.Methods
	next.Normalize()
	if next.On(zapret.Sites) && len(next.Sites) == 0 {
		return errors.New("добавьте хотя бы один сайт или снимите «Свои сайты»")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := c.Store.SaveZapret(next); err != nil {
		return err
	}
	c.zapretCfg = next
	c.Log.Info("zapret: settings saved", "on", next.Enabled, "targets", len(next.Targets), "sites", len(next.Sites))
	c.zapretApplyLocked()
	c.changed()
	return nil
}

// ZapretPickCancel stops an auto-pick under way.
func (c *Controller) ZapretPickCancel() {
	c.pickMu.Lock()
	defer c.pickMu.Unlock()
	if c.pickCancel != nil {
		c.pickCancel()
	}
}

// ZapretPick finds, for every service ticked, a method that opens it on
// this network: first without any bypass (not blocked → none needed),
// then method by method, each with a winws2 of its own, until every
// service opens or the methods run out. What it found is kept for this
// network, and the bypass starts with it.
func (c *Controller) ZapretPick() (ZapretView, error) {
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	cfg := c.zapretCfg
	if c.zapretErr != nil || len(cfg.Targets) == 0 {
		p, b, _ := c.pickState()
		if c.zapretErr != nil {
			return c.zapretInfoLocked(p, b), fmt.Errorf("zapret.json не загружен: %v", c.zapretErr)
		}
		return c.zapretInfoLocked(p, b), errors.New("выберите, что обходить")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pick := &ZapretPickView{Running: true, Step: "Готовлю zapret2…", Total: len(zapret.Methods) + 1,
		Results: map[zapret.Target]string{}, Diagnosis: map[zapret.Target]ZapretDiag{}}
	c.pickMu.Lock()
	c.zapretPick, c.pickCancel = pick, cancel
	c.pickMu.Unlock()
	update := func(f func(p *ZapretPickView)) {
		c.pickMu.Lock()
		f(pick)
		c.pickMu.Unlock()
		c.changed()
	}
	finish := func(err error) (ZapretView, error) {
		update(func(p *ZapretPickView) {
			p.Running = false
			if err != nil {
				p.Error = err.Error()
			}
		})
		c.pickMu.Lock()
		c.pickCancel = nil
		c.pickMu.Unlock()
		c.zapretApplyLocked()
		p, b, _ := c.pickState()
		return c.zapretInfoLocked(p, b), err
	}
	dir, err := c.zapretReady(ctx)
	if err != nil {
		return finish(err)
	}
	// The user's bypass keeps running: it skips the probes' ports.
	key, _ := c.zapretNetKey()
	if err := zapret.WriteLists(c.ZapretLists, cfg.Sites, c.zapretServers()); err != nil {
		return finish(err)
	}
	checkAll := func(slot int, ts []zapret.Target) map[zapret.Target]zapret.Result {
		out := map[zapret.Target]zapret.Result{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range ts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := zapretCheckFunc(ctx, slot, zapret.Checks(t, cfg.Sites))
				mu.Lock()
				out[t] = r
				mu.Unlock()
			}()
		}
		wg.Wait()
		return out
	}

	// Without a bypass: what is blocked, and how. A service the user sent
	// through the VPN is not checked: its traffic may take the tunnel.
	left := slices.DeleteFunc(slices.Clone(cfg.Targets), func(t zapret.Target) bool { return cfg.Methods[t] == zapret.VPN })
	if len(left) == 0 {
		return finish(errors.New("все выбранные сервисы идут через VPN: подбирать нечего"))
	}
	update(func(p *ZapretPickView) {
		p.Step = "Проверяю без обхода: что блокируется и как"
	})
	for t, r := range checkAll(0, left) {
		if r.OK {
			update(func(p *ZapretPickView) { p.Results[t] = zapret.None })
			left = slices.DeleteFunc(left, func(x zapret.Target) bool { return x == t })
			continue
		}
		d := r.Diagnosis()
		update(func(p *ZapretPickView) {
			p.Diagnosis[t] = ZapretDiag{Kind: d.Kind, Text: d.Kind.Explain(), Detail: d.String(), Bypass: r.Bypassable()}
		})
	}
	update(func(p *ZapretPickView) { p.Done = 1 })
	if ctx.Err() != nil {
		return finish(errors.New("подбор остановлен"))
	}

	// Every method at once, each in its own winws2 that sees only the
	// probes of its slot: the fastest that opens a target goes first, the
	// others that open it are its spares.
	type timed struct {
		id string
		d  time.Duration
	}
	works := map[zapret.Target][]timed{}
	if len(left) > 0 {
		update(func(p *ZapretPickView) {
			p.Step = fmt.Sprintf("Пробую %d методов обхода сразу", len(zapret.Methods))
		})
		testers := make([]*zapret.Runner, len(zapret.Methods))
		defer func() {
			for _, r := range testers {
				if r != nil {
					r.Stop()
				}
			}
		}()
		for i, m := range zapret.Methods {
			plans := map[zapret.Target]zapret.Plan{}
			for _, t := range left {
				plans[t] = zapret.Plan{Methods: []string{m.ID}}
			}
			args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: c.ZapretLists, Plans: plans, Filter: zapret.ProbeOnly(i + 1)})
			if err != nil {
				return finish(err)
			}
			testers[i] = &zapret.Runner{Exe: filepath.Join(dir, "winws2.exe"), Log: c.Log, Spawn: zapretSpawn}
			testers[i].Start(args)
		}
		select {
		case <-ctx.Done():
			return finish(errors.New("подбор остановлен"))
		case <-time.After(zapretSettle):
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		var started int
		var firstErr string
		for i, m := range zapret.Methods {
			if st := testers[i].Status(); st.State != zapret.Running {
				c.Log.Warn("zapret: tester not running", "method", m.ID, "err", st.Error)
				if firstErr == "" {
					firstErr = st.Error
				}
				update(func(p *ZapretPickView) { p.Done++ })
				continue
			}
			started++
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t, r := range checkAll(i+1, left) {
					if r.OK && ctx.Err() == nil {
						mu.Lock()
						works[t] = append(works[t], timed{m.ID, r.Elapsed})
						mu.Unlock()
					}
				}
				testers[i].Stop()
				update(func(p *ZapretPickView) { p.Done++ })
			}()
		}
		wg.Wait()
		if started == 0 {
			return finish(fmt.Errorf("winws2 не работает: %s", firstErr))
		}
	}
	if ctx.Err() != nil {
		return finish(errors.New("подбор остановлен"))
	}
	working := map[zapret.Target][]string{}
	results := map[zapret.Target]string{}
	for _, t := range left {
		ws := works[t]
		// The fastest first; equal times keep the library's order.
		slices.SortStableFunc(ws, func(a, b timed) int {
			if d := cmp.Compare(a.d, b.d); d != 0 {
				return d
			}
			return cmp.Compare(methodIndex(a.id), methodIndex(b.id))
		})
		for _, w := range ws {
			working[t] = append(working[t], w.id)
		}
		results[t] = "" // none worked
		if len(ws) > 0 {
			results[t] = ws[0].id
		}
	}
	update(func(p *ZapretPickView) {
		maps.Copy(p.Results, results)
		p.Working = working
	})
	// Kept for this network: what opens, and «not blocked». A new map: the
	// page may be reading the old one.
	c.pickMu.Lock()
	found := map[zapret.Target]string{}
	for t, m := range c.zapretPick.Results {
		if m != "" {
			found[t] = m
		}
	}
	c.pickMu.Unlock()
	picked := maps.Clone(c.zapretCfg.Picked)
	if picked == nil {
		picked = map[string]zapret.Picked{}
	}
	picked[key] = zapret.Picked{At: time.Now(), Methods: found, Working: working}
	trimPicked(picked)
	c.zapretCfg.Picked = picked
	if err := c.Store.SaveZapret(c.zapretCfg); err != nil {
		return finish(err)
	}
	update(func(p *ZapretPickView) { p.Step = "Готово" })
	c.Log.Info("zapret: methods picked", "network", key != "", "found", len(found), "left", len(left))
	return finish(nil)
}

// trimPicked keeps the newest zapret.MaxNetKeys networks.
func trimPicked(m map[string]zapret.Picked) {
	for len(m) > zapret.MaxNetKeys {
		oldest, first := "", true // "" is a key too (an unknown network)
		for k, p := range m {
			if first || p.At.Before(m[oldest].At) {
				oldest, first = k, false
			}
		}
		delete(m, oldest)
	}
}
