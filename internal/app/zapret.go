package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
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
	// zapretExtra: HyRoute's own hosts in the running bypass's lists (the
	// Cloudflare domains of «Telegram без VPN»; nil: none).
	zapretExtra map[zapret.Target][]string
	zapretKey   string             // the network zapretArgs were built for
	zapretNet   string             // its name, for the page
	zapretStop  context.CancelFunc // ends zapretWatch
	zapretPick  *ZapretPickView
	pickCancel  context.CancelFunc
	// pickMu guards zapretPick, pickCancel, zapretBusy and zapretShown
	// (read by ZapretInfo while an apply or a pick holds zapretMu).
	pickMu      sync.Mutex
	zapretBusy  string      // «Скачиваю zapret2…» while staging
	zapretShown *ZapretView // the last view built with zapretMu held
	// Self-healing (zapretHeal): healStop ends it (zapretMu); healNote,
	// healAt: its last finding for the page; autoPicks: when it last
	// picked on a network and whether that found anything (pickMu).
	healStop  context.CancelFunc
	healWG    sync.WaitGroup
	healNote  string
	healAt    time.Time
	autoPicks map[string]autoPick
}

// autoPick is a pick self-healing started on a network.
type autoPick struct {
	at    time.Time
	found bool // it found a method for every service it was for
}

// ZapretRulePrefix starts the name of a rule the bypass keeps.
const ZapretRulePrefix = "Обход DPI: "

// Test hooks.
var (
	zapretSettle = 1500 * time.Millisecond // winws2 opens WinDivert and reads its lists
	// zapretStartWait: how long a pick waits for its testers to start (a
	// busy or just woken computer, an antivirus scanning each winws2).
	zapretStartWait = 15 * time.Second
	// zapretStagger spaces the testers' starts: twelve cygwin processes
	// started at once start slowly and some fail to initialize
	// (0xC0000142).
	zapretStagger = 100 * time.Millisecond
	// The generator: candidates tried around what worked, over the whole
	// space when nothing did, the strategies kept per target, the time.
	zapretRefine = 24
	// zapretRefineAuto: self-healing's pick tries one batch around what
	// worked (the fastest still wins, checked twice), the whole space only
	// when nothing worked.
	zapretRefineAuto = 12
	zapretBroad      = 60
	zapretKeep       = 8
	zapretPickBudget = 3 * time.Minute
	zapretSeed       = rand.Uint64
	zapretCheckFunc  = func(ctx context.Context, slot int, urls []string) zapret.Result {
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
	// Telegram: «Telegram без VPN» (tgws.go).
	Telegram TelegramView `json:"telegram"`
	// Heal: what self-healing last found ("" = nothing yet), and when.
	HealNote string `json:"healNote,omitempty"`
	HealAt   int64  `json:"healAt,omitempty"` // Unix ms
}

// ZapretDiag is how a target is blocked.
type ZapretDiag struct {
	Kind   zapret.Kind `json:"kind"`
	Text   string      `json:"text"`   // the kind, for the user
	Detail string      `json:"detail"` // the address and what happened
	// Bypass: a method can open it; otherwise only the VPN can.
	Bypass bool `json:"bypass"`
}

// methodIndex orders equal times: the library's order, generated ones
// after it.
func methodIndex(id string) int {
	if i := slices.IndexFunc(zapret.Methods, func(m zapret.Method) bool { return m.ID == id }); i >= 0 {
		return i
	}
	return len(zapret.Methods)
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
	// Generated: made by the generator (on this network), not the library.
	Generated bool `json:"generated,omitempty"`
}

// ZapretPickView is an auto-pick under way or just done.
type ZapretPickView struct {
	Running bool                     `json:"running"`
	Step    string                   `json:"step"`
	Done    int                      `json:"done"`
	Total   int                      `json:"total"`
	Results map[zapret.Target]string `json:"results"` // a method ID, "none", or "" (none worked)
	// Tried: strategies tried (the library and generated ones).
	Tried int `json:"tried"`
	// Working: every method that opened the target, fastest first.
	Working map[zapret.Target][]string `json:"working,omitempty"`
	// Diagnosis: how a target is blocked without a bypass.
	Diagnosis map[zapret.Target]ZapretDiag `json:"diagnosis,omitempty"`
	Error     string                       `json:"error,omitempty"`
	// Skipped: own sites left out: they do not open even without a bypass
	// in a way none beats ("proxifile.com: имя сайта не находится").
	Skipped []string `json:"skipped,omitempty"`
	// Auto: started by self-healing, not by the user; Why: what made it.
	Auto bool   `json:"auto,omitempty"`
	Why  string `json:"why,omitempty"`
}

// ZapretInput is what the page saves.
type ZapretInput struct {
	Enabled bool                     `json:"enabled"`
	Targets []zapret.Target          `json:"targets"`
	Sites   []string                 `json:"sites"`
	Methods map[zapret.Target]string `json:"methods"`
	// AutoHeal: nil keeps the setting.
	AutoHeal *bool `json:"autoHeal,omitempty"`
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
	if err := zapret.WriteLists(c.ZapretLists, c.zapretCfg.Sites, c.zapretServers(), c.zapretExtra); err != nil {
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
	c.tgApplyLocked() // Telegram's proxy: on its own switch
	// Cloudflare before the VPN once it is known whether winws2 carries it.
	defer c.tgCloudflareLocked()
	defer c.zapretWatchLocked(cfg)
	defer c.zapretHealLocked(cfg)
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
	extra := c.cloudflareListsLocked(plans)
	if err := zapret.WriteLists(c.ZapretLists, cfg.Sites, c.zapretServers(), extra); err != nil {
		c.Log.Error("zapret: lists not written", "err", err)
		run.Stop()
		return
	}
	args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: c.ZapretLists, Plans: plans, Sites: cfg.Sites, Filter: zapret.ProbeExclude()})
	if err != nil {
		c.Log.Error("zapret: command line not built", "err", err)
		run.Stop()
		return
	}
	if slices.Equal(args, c.zapretArgs) && run.Status().State != zapret.Off {
		c.zapretExtra = extra
		return
	}
	c.zapretArgs, c.zapretExtra = args, extra
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
	out := zapretTargetRules(cfg)
	if cfg.Telegram.Enabled {
		out = append(out, telegramRule())
	}
	return out
}

func zapretTargetRules(cfg zapret.Settings) []rules.Rule {
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
		// The VPN by the user's own rules: none of ours for the sites,
		// which those rules take through the VPN, every one (ZapretViaVPN
		// checks); Discord's voice, addresses without names, through the
		// main server.
		act, prof := rules.Direct, ""
		byRules := false
		if cfg.Methods[t] == zapret.VPN {
			act, prof = rules.Tunnel, cfg.Via[t]
			if prof == zapret.ViaRules {
				byRules, prof = true, ""
			}
		}
		if doms := zapretRuleSites(t, cfg.Sites); len(doms) > 0 && !byRules {
			out = append(out, rules.Rule{Name: ZapretRulePrefix + zapret.TargetName(t), Domains: doms, Action: act, Profile: prof})
		}
		if t == zapret.Discord {
			// Voice goes to addresses without names, from the program.
			out = append(out, rules.Rule{Name: ZapretRulePrefix + "Discord (голос)",
				Apps:     []rules.AppMatch{{Pattern: "Discord.exe", InheritChildren: true}},
				Protocol: "udp", Ports: rules.PortList{"19294-19344", "50000-50100"}, Action: act, Profile: prof})
		}
	}
	return out
}

func isZapretRule(r rules.Rule) bool { return strings.HasPrefix(r.Name, ZapretRulePrefix) }

// zapretRuleSites are service t's sites as rule items: a name with every
// name under it («.youtube.com»: a plain name in a rule is that name only,
// and the service's servers are under it), an address or network as it is.
func zapretRuleSites(t zapret.Target, sites []string) []string {
	var out []string
	for _, d := range zapret.Domains(t, sites) {
		if len(zapret.SiteNets([]string{d})) == 0 {
			d = "." + d
		}
		out = append(out, d)
	}
	return out
}

// zapretProbe is put in front of a service's site for a name under it no
// rule names itself: a rule for the plain name alone does not take it.
const zapretProbe = "hyroute-probe."

// sameZapretRule: r is the kept rule w (its ID and switch aside).
func sameZapretRule(r, w rules.Rule) bool {
	return r.Name == w.Name && slices.Equal(r.Domains, w.Domains) && r.Action == w.Action && r.Profile == w.Profile && slices.Equal(r.Fallback, w.Fallback) && r.Protocol == w.Protocol &&
		slices.Equal(r.Ports, w.Ports) && len(r.Apps) == len(w.Apps)
}

// syncZapretRules keeps the rules «Обход DPI: …» at the top of the active
// rule profile, as the settings want them. A rule the user switched off
// stays off.
func (c *Controller) syncZapretRules(cfg zapret.Settings) {
	// A server or group chosen for «через VPN» and deleted since: the
	// main server takes its place, as for settings from before the
	// choice; a rule through a missing one would refuse every connection.
	c.mu.Lock()
	var gone []zapret.Target
	for t, v := range cfg.Via {
		if v != zapret.ViaRules && !c.targetExistsLocked(v) {
			gone = append(gone, t)
		}
	}
	c.mu.Unlock()
	if len(gone) > 0 {
		cfg.Via = cloneMap(cfg.Via)
		for _, t := range gone {
			delete(cfg.Via, t)
		}
	}
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
		v.HealNote, v.HealAt = c.healState()
		return v
	}
	defer c.zapretMu.Unlock()
	return c.zapretInfoLocked(pick, busy)
}

// zapretInfoLocked builds the view (zapretMu held).
func (c *Controller) zapretInfoLocked(pick *ZapretPickView, busy string) ZapretView {
	v := ZapretView{Available: c.ZapretPrepare != nil, Pick: pick, Busy: busy}
	v.HealNote, v.HealAt = c.healState()
	v.Telegram = c.telegramViewLocked()
	c.mu.Lock()
	v.HasServer = c.mainTargetLocked() != ""
	c.mu.Unlock()
	for _, m := range zapret.Methods {
		v.Methods = append(v.Methods, ZapretMethodView{ID: m.ID, Name: m.Name})
	}
	key, name := c.zapretKey, c.zapretNet // as of the last apply: the page does not read the network
	v.Network = name
	// The generated strategies this network uses, the user's fixed ones
	// and the pick's: they can be chosen too, and the page names them.
	gen := func(id string) {
		if !strings.HasPrefix(id, zapret.GenPrefix) || slices.ContainsFunc(v.Methods, func(m ZapretMethodView) bool { return m.ID == id }) {
			return
		}
		if m, ok := zapret.FindMethod(id); ok {
			v.Methods = append(v.Methods, ZapretMethodView{ID: id, Name: m.Name, Generated: true})
		}
	}
	for _, ws := range c.zapretCfg.Picked[key].Working {
		for _, id := range ws {
			gen(id)
		}
	}
	for _, id := range c.zapretCfg.Methods {
		gen(id)
	}
	if pick != nil {
		for _, ws := range pick.Working {
			for _, id := range ws {
				gen(id)
			}
		}
	}
	cfg := c.zapretCfg
	// A copy of its own: the page may show this view later without
	// zapretMu (pickState) while a save changes the maps of zapretCfg.
	v.Settings = cloneZapretSettings(cfg)
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
			switch via := cfg.Via[t]; {
			case via == zapret.ViaRules:
				tv.Using = "без обхода, по вашим правилам"
			case via != "":
				tv.Using = "через «" + c.profileName(via) + "», без обхода"
			default:
				tv.Using = "через VPN, без обхода"
			}
			if !v.HasServer && cfg.Via[t] != zapret.ViaRules {
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

// cloneZapretSettings copies s down to its maps and lists: a copy read
// without zapretMu while a save normalizes the maps of zapretCfg in place.
func cloneZapretSettings(s zapret.Settings) zapret.Settings {
	s.Targets, s.Sites = slices.Clone(s.Targets), slices.Clone(s.Sites)
	s.Telegram.Workers = slices.Clone(s.Telegram.Workers)
	s.Methods, s.Via = cloneMap(s.Methods), cloneMap(s.Via)
	if s.AutoHeal != nil {
		on := *s.AutoHeal
		s.AutoHeal = &on
	}
	if s.Picked != nil {
		picked := make(map[string]zapret.Picked, len(s.Picked))
		for k, p := range s.Picked {
			p.Methods = cloneMap(p.Methods)
			if p.Working != nil {
				w := make(map[zapret.Target][]string, len(p.Working))
				for t, ms := range p.Working {
					w[t] = slices.Clone(ms)
				}
				p.Working = w
			}
			p.SkippedSites = slices.Clone(p.SkippedSites)
			picked[k] = p
		}
		s.Picked = picked
	}
	return s
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
	// An entry that is neither a site nor a public address or network is
	// named, not dropped without a word.
	for _, d := range in.Sites {
		if strings.TrimSpace(d) != "" && zapret.NormalizeSite(d) == "" {
			return fmt.Errorf("«%s» — не имя сайта и не адрес. Адрес или сеть должны быть внешними (не локальными) и не шире /8 (IPv6 — /16)", strings.TrimSpace(d))
		}
	}
	next := c.zapretCfg
	next.Enabled, next.Targets, next.Sites, next.Methods = in.Enabled, in.Targets, in.Sites, in.Methods
	next.Via = cloneMap(next.Via)
	if in.AutoHeal != nil {
		v := *in.AutoHeal
		next.AutoHeal = &v
		if v {
			next.AutoHeal = nil // the default
		}
	}
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
	c.pickMu.Lock()
	busy := c.pickCancel != nil && c.zapretPick != nil && c.zapretPick.Running
	c.pickMu.Unlock()
	if busy {
		return c.ZapretInfo(), errors.New("подбор уже идёт")
	}
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	return c.zapretPickLocked("")
}

// zapretPickLocked is the pick; why is set when self-healing started it.
func (c *Controller) zapretPickLocked(why string) (ZapretView, error) {
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
		Results: map[zapret.Target]string{}, Diagnosis: map[zapret.Target]ZapretDiag{}, Auto: why != "", Why: why}
	checks := map[zapret.Target][]string{}
	for _, t := range cfg.Targets {
		checks[t] = c.zapretChecks(t, cfg.Sites, nil)
	}
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
	if err := zapret.WriteLists(c.ZapretLists, cfg.Sites, c.zapretServers(), c.zapretExtra); err != nil {
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
				r := zapretCheckFunc(ctx, slot, checks[t])
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
	// Nor are own sites given only by address: nothing to check them by.
	left := slices.DeleteFunc(slices.Clone(cfg.Targets), func(t zapret.Target) bool {
		return cfg.Methods[t] == zapret.VPN || len(zapret.Checks(t, cfg.Sites)) == 0
	})
	if len(left) == 0 {
		return finish(errors.New("подбирать нечего: выбранные сервисы идут через VPN или заданы только адресами (их подбор не проверяет)"))
	}
	update(func(p *ZapretPickView) {
		p.Step = "Проверяю без обхода: что блокируется и как"
	})
	// Own sites: one that does not exist or is blocked by address would
	// fail the others' pick. They are left out, and said so.
	var skipped []string
	if slices.Contains(left, zapret.Sites) {
		r := zapretCheckFunc(ctx, 0, zapret.SiteProbes(cfg.Sites))
		var notes []string
		for _, f := range r.Failed {
			if !f.Kind.Bypassable() && !slices.Contains(skipped, f.Host) {
				skipped = append(skipped, f.Host)
				notes = append(notes, f.Host+" — "+f.Kind.Explain())
			}
		}
		if cs := zapret.ChecksSkip(zapret.Sites, cfg.Sites, skipped); len(skipped) > 0 && len(cs) > 0 {
			checks[zapret.Sites] = cs
			update(func(p *ZapretPickView) { p.Skipped = notes })
		} else {
			skipped = nil // all of them: the diagnosis says why
		}
	}
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

	// The generator, in rounds of candidates tried at once, each in its own
	// winws2 that sees only the probes of its slot:
	//  1. the library;
	//  2. strategies one change away from what worked (a faster one,
	//     spares), or, for a target nothing opened, a spread over the whole
	//     space; until the time is up;
	//  3. the best of each target once more: a strategy is kept only when
	//     it opened it every time.
	type timed struct {
		id string
		d  time.Duration
	}
	deadline := time.Now().Add(zapretPickBudget)
	tried := map[string]bool{}
	works := map[zapret.Target][]timed{}
	round := func(cands []string, targets []zapret.Target) (map[zapret.Target][]timed, error) {
		out := map[zapret.Target][]timed{}
		retried := false
		for len(cands) > 0 && ctx.Err() == nil {
			batch := cands[:min(len(cands), zapret.ProbeSlots-1)]
			testers := make([]*zapret.Runner, len(batch))
			for i, id := range batch {
				tried[id] = true
				plans := map[zapret.Target]zapret.Plan{}
				for _, t := range targets {
					plans[t] = zapret.Plan{Methods: []string{id}}
				}
				args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: c.ZapretLists, Plans: plans, Sites: cfg.Sites, Filter: zapret.ProbeOnly(i + 1)})
				if err != nil {
					for _, r := range testers[:i] {
						r.Stop() // started: none left on its probe ports
					}
					return nil, err
				}
				testers[i] = &zapret.Runner{Exe: filepath.Join(dir, "winws2.exe"), Log: c.Log, Spawn: zapretSpawn}
				if i > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(zapretStagger):
					}
				}
				testers[i].Start(args)
			}
			// Until each has started (or failed), then a moment to settle.
			up := time.Now().Add(zapretStartWait)
			for ctx.Err() == nil && time.Now().Before(up) && slices.ContainsFunc(testers, func(r *zapret.Runner) bool { return r.Status().State == zapret.Off }) {
				select {
				case <-ctx.Done():
				case <-time.After(100 * time.Millisecond):
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(zapretSettle):
			}
			var mu sync.Mutex
			var wg sync.WaitGroup
			started, firstErr := 0, ""
			for i, id := range batch {
				if st := testers[i].Status(); st.State != zapret.Running {
					c.Log.Warn("zapret: tester not running", "method", id, "state", st.State, "err", st.Error)
					if firstErr == "" {
						firstErr = st.Error
						if firstErr == "" {
							firstErr = fmt.Sprintf("не успел запуститься за %d с — компьютер занят или антивирус проверяет winws2", int(zapretStartWait.Seconds()))
						}
					}
					testers[i].Stop()
					update(func(p *ZapretPickView) { p.Done++ })
					continue
				}
				started++
				wg.Add(1)
				go func() {
					defer wg.Done()
					for t, r := range checkAll(i+1, targets) {
						if r.OK && ctx.Err() == nil {
							mu.Lock()
							out[t] = append(out[t], timed{id, r.Elapsed})
							mu.Unlock()
						}
					}
					testers[i].Stop()
					update(func(p *ZapretPickView) { p.Done++; p.Tried = len(tried) })
				}()
			}
			wg.Wait()
			if started == 0 {
				if !retried && ctx.Err() == nil {
					// Once more after a pause: the same batch.
					retried = true
					update(func(p *ZapretPickView) { p.Done -= len(batch) })
					c.Log.Warn("zapret: no tester started; the batch again", "err", firstErr)
					select {
					case <-ctx.Done():
					case <-time.After(3 * time.Second):
					}
					continue
				}
				return nil, fmt.Errorf("winws2 не запускается: %s", firstErr)
			}
			retried = false
			cands = cands[len(batch):]
		}
		return out, nil
	}
	fastest := func(ws []timed) []timed {
		ws = slices.Clone(ws)
		slices.SortStableFunc(ws, func(a, b timed) int {
			if d := cmp.Compare(a.d, b.d); d != 0 {
				return d
			}
			return cmp.Compare(methodIndex(a.id), methodIndex(b.id))
		})
		return ws
	}
	// working: the variants that opened some target (one that opened two
	// counts once).
	workingCount := func() int {
		seen := map[string]bool{}
		for _, ws := range works {
			for _, w := range ws {
				seen[w.id] = true
			}
		}
		return len(seen)
	}
	merge := func(got map[zapret.Target][]timed) {
		for t, ws := range got {
			works[t] = append(works[t], ws...)
		}
	}
	if len(left) > 0 {
		// 1. The library, and what worked here before (spares the
		// generator made among them).
		var lib []string
		for _, m := range zapret.Methods {
			lib = append(lib, m.ID)
		}
		for _, t := range left {
			for _, id := range cfg.Picked[key].Working[t] {
				if !slices.Contains(lib, id) {
					lib = append(lib, id)
				}
			}
		}
		update(func(p *ZapretPickView) {
			p.Step = fmt.Sprintf("Пробую %d известных и найденных раньше методов сразу", len(lib))
			p.Total = 1 + len(lib)
		})
		got, err := round(lib, left)
		if err != nil {
			return finish(err)
		}
		merge(got)

		// 2. Around what worked, or over the whole space.
		var cands []string
		add := func(id string) {
			if !tried[id] && !slices.Contains(cands, id) {
				cands = append(cands, id)
			}
		}
		lost := false
		for _, t := range left {
			ws := fastest(works[t])
			if len(ws) == 0 {
				lost = true
				continue
			}
			for _, w := range ws[:min(2, len(ws))] {
				if st, ok := zapret.AsStrategy(w.id); ok {
					for _, n := range zapret.Neighbors(st) {
						add(n.ID())
					}
				}
			}
		}
		budget := zapretRefine
		if why != "" {
			budget = zapretRefineAuto
		}
		if lost {
			known := zapret.Known()
			for _, st := range known {
				add(st.ID())
			}
			for _, st := range zapret.Broad(zapretBroad, zapretSeed()) {
				add(st.ID())
			}
			budget = zapretRefine + len(known) + zapretBroad
		}
		// Neighbors of the fastest first, then Flowseal's recipes and the
		// spread.
		cands = cands[:min(len(cands), budget)]
		for len(cands) > 0 && ctx.Err() == nil && time.Now().Before(deadline) {
			batch := cands[:min(len(cands), zapret.ProbeSlots-1)]
			cands = cands[len(batch):]
			update(func(p *ZapretPickView) {
				p.Step = fmt.Sprintf("Генерирую свои варианты: проверено %d, рабочих найдено %d", len(tried), workingCount())
				p.Total = p.Done + len(batch) + len(cands) + 1
			})
			got, err := round(batch, left)
			if err != nil {
				return finish(err)
			}
			merge(got)
		}

		// 3. The best once more.
		var again []string
		for _, t := range left {
			for _, w := range fastest(works[t])[:min(zapretKeep, len(works[t]))] {
				if !slices.Contains(again, w.id) {
					again = append(again, w.id)
				}
			}
		}
		if len(again) > 0 && ctx.Err() == nil {
			update(func(p *ZapretPickView) {
				p.Step = fmt.Sprintf("Перепроверяю %d лучших", len(again))
				p.Total = p.Done + len(again)
			})
			got, err := round(again, left)
			if err != nil {
				return finish(err)
			}
			for _, t := range left {
				var kept []timed
				for _, w := range works[t] {
					if i := slices.IndexFunc(got[t], func(g timed) bool { return g.id == w.id }); i >= 0 {
						kept = append(kept, timed{w.id, (w.d + got[t][i].d) / 2})
					}
				}
				works[t] = kept
			}
		}
	}
	if ctx.Err() != nil {
		return finish(errors.New("подбор остановлен"))
	}
	working := map[zapret.Target][]string{}
	results := map[zapret.Target]string{}
	for _, t := range left {
		ws := fastest(works[t])
		for _, w := range ws[:min(zapretKeep, len(ws))] {
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
	picked[key] = zapret.Picked{At: time.Now(), Methods: found, Working: working, SkippedSites: skipped}
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

// ZapretRouteRule is a rule of the user's that decides some of a
// service's sites ("" ID: «Всё остальное»).
type ZapretRouteRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Route   string   `json:"route"` // «через «NL»», «напрямую», «блокировка»
	Tunnel  bool     `json:"tunnel"`
	Profile string   `json:"profile"`
	Sites   []string `json:"sites"`
	// Own: the rule is about this service only (its sites, its geosite
	// list): its server can be changed for it without touching others.
	Own bool `json:"own"`
}

// ZapretRoute is where the user's rules (the bypass's own aside) send a
// service: shown before it is sent through the VPN.
type ZapretRoute struct {
	Target zapret.Target     `json:"target"`
	Name   string            `json:"name"`
	By     []ZapretRouteRule `json:"by"`
	// Tunnel: every site of it goes through the VPN by those rules.
	Tunnel bool `json:"tunnel"`
	// Via: the current choice (zapret.Settings.Via).
	Via string `json:"via"`
}

// zapretGeo: the geosite lists that are a service's own.
var zapretGeo = map[zapret.Target][]string{zapret.YouTube: {"youtube"}, zapret.Discord: {"discord"}}

// ZapretRoute tells where the user's rules send service t.
func (c *Controller) ZapretRoute(t zapret.Target) (ZapretRoute, error) {
	if !slices.Contains(zapret.Targets, t) {
		return ZapretRoute{}, errors.New("неизвестный сервис")
	}
	c.zapretMu.Lock()
	cfg := c.zapretCfg
	via := cfg.Via[t]
	sites := slices.Clone(cfg.Sites)
	c.zapretMu.Unlock()
	c.mu.Lock()
	rc := c.settings.Config.Clone()
	main := c.mainTargetLocked()
	c.mu.Unlock()
	rc.Rules = slices.DeleteFunc(rc.Rules, isZapretRule)
	set, err := rules.Compile(rc)
	if err != nil {
		return ZapretRoute{}, err
	}
	set.Main = main
	res := ZapretRoute{Target: t, Name: zapret.TargetName(t), By: []ZapretRouteRule{}, Tunnel: true, Via: via}
	doms := zapret.SiteNames(zapret.Domains(t, sites))
	sub := rules.Subject{Proto: 6, Dst: netip.AddrPortFrom(netip.Addr{}, 443)}
	for _, d := range doms {
		// The site and a name under it: the service's servers are there.
		first := -1
		for _, name := range []string{d, zapretProbe + d} {
			r := set.EvaluateDomain(sub, name, rules.SrcSNI)
			i := slices.IndexFunc(res.By, func(b ZapretRouteRule) bool { return b.ID == r.RuleID && b.Name == r.Rule })
			if i < 0 {
				b := ZapretRouteRule{ID: r.RuleID, Name: r.Rule, Tunnel: r.Action == rules.Tunnel, Profile: r.Profile}
				if r.RuleID == "" {
					b.Name = "Всё остальное"
				}
				switch r.Action {
				case rules.Direct:
					b.Route = "напрямую"
				case rules.Block:
					b.Route = "блокировка"
				default:
					b.Route = "через «" + c.profileName(r.Profile) + "»"
					if r.Profile == "" {
						b.Route = "через VPN — но сервер не выбран"
					}
				}
				if k := slices.IndexFunc(rc.Rules, func(x rules.Rule) bool { return x.ID != "" && x.ID == r.RuleID }); k >= 0 {
					b.Own = ownRule(rc.Rules[k], t, sites)
				}
				res.By = append(res.By, b)
				i = len(res.By) - 1
			}
			switch {
			case name == d:
				res.By[i].Sites = append(res.By[i].Sites, d)
				first = i
			case i != first:
				res.By[i].Sites = append(res.By[i].Sites, "*."+d)
			}
			if r.Action != rules.Tunnel || r.Profile == "" {
				res.Tunnel = false
			}
		}
	}
	// Addresses: the rules are not asked about them, the bypass keeps its
	// rule for them.
	if len(doms) == 0 || len(zapret.SiteNets(zapret.Domains(t, sites))) > 0 {
		res.Tunnel = false
	}
	return res, nil
}

// ownRule: rule r is about service t alone: only its sites or its geosite
// lists, for any program, port and protocol.
func ownRule(r rules.Rule, t zapret.Target, sites []string) bool {
	items := r.AllDomains()
	if len(items) == 0 || len(r.AllApps()) > 0 || len(r.Ports) > 0 || r.Protocol != "" && r.Protocol != "any" {
		return false
	}
	doms := zapret.SiteNames(zapret.Domains(t, sites))
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		if g, ok := strings.CutPrefix(it, "geosite:"); ok && slices.Contains(zapretGeo[t], g) {
			continue
		}
		n := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(it, "*."), "."), "domain:")
		n = strings.TrimPrefix(n, "full:")
		if !slices.ContainsFunc(doms, func(d string) bool { return n == d || strings.HasSuffix(n, "."+d) }) {
			return false
		}
	}
	return true
}

// ZapretViaInput sends a service through the VPN: Via is zapret.ViaRules
// (by the user's rules), "" (the main server) or a server or group ID.
// EditRule: the ID of the user's own rule for the service (ZapretRoute's
// Own) to route through Via instead of a rule of the bypass's.
type ZapretViaInput struct {
	Target   zapret.Target `json:"target"`
	Via      string        `json:"via"`
	EditRule string        `json:"editRule"`
}

// ZapretViaVPN sends a service through the VPN as chosen.
func (c *Controller) ZapretViaVPN(in ZapretViaInput) error {
	if !slices.Contains(zapret.Targets, in.Target) {
		return errors.New("неизвестный сервис")
	}
	if in.Via != zapret.ViaRules && in.Via != "" {
		c.mu.Lock()
		ok := c.targetExistsLocked(in.Via)
		c.mu.Unlock()
		if !ok {
			return errors.New("сервер не найден: обновите страницу")
		}
	}
	// By the user's rules only when they take every site of it through the
	// VPN: else a site of it would go wherever the rest of the rules say.
	covered := func() bool {
		r, err := c.ZapretRoute(in.Target)
		return err == nil && r.Tunnel
	}
	if in.Via == zapret.ViaRules && !covered() {
		return errors.New("ваши правила ведут через VPN не все сайты сервиса: выберите сервер")
	}
	via := in.Via
	if in.EditRule != "" {
		if in.Via == zapret.ViaRules {
			return errors.New("выберите сервер")
		}
		// Before the user's rule changes: with zapret.json not loaded the
		// choice would not be saved, and the rule would stay changed.
		c.zapretMu.Lock()
		zerr := c.zapretErr
		c.zapretMu.Unlock()
		if zerr != nil {
			return fmt.Errorf("zapret.json не загружен, изменения не сохраняются: %v", zerr)
		}
		c.zapretMu.Lock()
		sites := slices.Clone(c.zapretCfg.Sites)
		c.zapretMu.Unlock()
		found := false
		_, err := c.editRules(func(rc *rules.Config) (bool, error) {
			for i := range rc.Rules {
				r := &rc.Rules[i]
				if r.ID != in.EditRule || isZapretRule(*r) {
					continue
				}
				if !ownRule(*r, in.Target, sites) {
					return false, errors.New("правило «" + r.Name + "» не только про этот сервис: выберите другой вариант")
				}
				found = true
				if r.Action == rules.Tunnel && r.Profile == in.Via && r.On() {
					return false, nil
				}
				r.Action, r.Profile, r.Enabled = rules.Tunnel, in.Via, nil
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return err
		}
		if !found {
			return errors.New("правило не найдено: список правил изменился, откройте выбор снова")
		}
		// The bypass steps aside only when the rules now take all of it;
		// else its rule takes the rest through the same server.
		if covered() {
			via = zapret.ViaRules
		}
	}
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	if c.zapretErr != nil {
		return fmt.Errorf("zapret.json не загружен, изменения не сохраняются: %v", c.zapretErr)
	}
	next := c.zapretCfg
	next.Methods, next.Via = cloneMap(next.Methods), cloneMap(next.Via)
	if next.Methods == nil {
		next.Methods = map[zapret.Target]string{}
	}
	if next.Via == nil {
		next.Via = map[zapret.Target]string{}
	}
	next.Methods[in.Target] = zapret.VPN
	if via == "" {
		delete(next.Via, in.Target)
	} else {
		next.Via[in.Target] = via
	}
	next.Normalize()
	if err := next.Validate(); err != nil {
		return err
	}
	if err := c.Store.SaveZapret(next); err != nil {
		return err
	}
	c.zapretCfg = next
	c.Log.Info("zapret: target through the VPN", "target", in.Target, "byRules", via == zapret.ViaRules, "edited", in.EditRule != "")
	c.zapretApplyLocked()
	c.changed()
	return nil
}

// zapretChecks are target t's checks (zapret.ChecksSkip) and, for YouTube,
// the video servers the browser reached lately (zapret.VideoChecks): the
// page and the redirector may open with a method that does not open them.
func (c *Controller) zapretChecks(t zapret.Target, sites, skip []string) []string {
	out := zapret.ChecksSkip(t, sites, skip)
	if t == zapret.YouTube {
		out = append(out, zapret.VideoChecks(c.videoServers())...)
	}
	return out
}

// videoServers: names of YouTube's video servers among the connections
// in memory, newest first. Read for a check and kept nowhere (statistics
// never record sites).
func (c *Controller) videoServers() []string {
	c.mu.Lock()
	reg := c.lastFlows
	c.mu.Unlock()
	if reg == nil {
		return nil
	}
	views := append(reg.Active(time.Now()), reg.Closed()...)
	slices.SortFunc(views, func(a, b flows.View) int { return b.Start.Compare(a.Start) })
	var out []string
	for _, v := range views {
		for _, h := range strings.Split(v.Domain, ",") {
			if h = strings.TrimSpace(h); h != "" {
				if _, ok := zapret.VideoServer(h); ok {
					out = append(out, h)
				}
			}
		}
		if len(out) >= 32 {
			break
		}
	}
	return out
}
