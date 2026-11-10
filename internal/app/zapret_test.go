package app

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/zapret"
)

type zapChild struct {
	done   chan struct{}
	killed func()
}

func (z *zapChild) Wait() error { <-z.done; return nil }
func (z *zapChild) Kill() error {
	select {
	case <-z.done:
	default:
		close(z.done)
		z.killed()
	}
	return nil
}

// zapFixture: winws2 never really runs; a check sees the arguments of the
// winws2 that serves its slot (none for slot 0, the check without a
// bypass: the user's own winws2 skips the probes).
func zapFixture(t *testing.T) (*Controller, func(slot int) string) {
	t.Helper()
	c, _ := newCtl(t)
	lists := t.TempDir()
	c.ZapretLists = lists
	c.ZapretPrepare = func(context.Context) (string, error) { return t.TempDir(), nil }
	var mu sync.Mutex
	bySlot := map[int]string{}
	spawn, settle, check, stagger := zapretSpawn, zapretSettle, zapretCheckFunc, zapretStagger
	t.Cleanup(func() {
		c.stopHeal()
		zapretSpawn, zapretSettle, zapretCheckFunc, zapretStagger = spawn, settle, check, stagger
	})
	zapretSettle, zapretStagger = time.Millisecond, 0
	zapretSpawn = func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) {
		slot := -1 // the user's bypass
		filter := func(f string) bool {
			return slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--wf-raw-filter=("+f+") and ") })
		}
		for i := 1; i < zapret.ProbeSlots; i++ {
			if filter(zapret.ProbeOnly(i)) {
				slot = i
			}
		}
		if slot < 0 && !filter(zapret.ProbeExclude()) {
			t.Errorf("the user's winws2 does not skip the probes: %v", args)
		}
		line := strings.Join(args, " ")
		mu.Lock()
		bySlot[slot] = line
		mu.Unlock()
		// Stopped, it no longer helps the checks.
		return &zapChild{done: make(chan struct{}), killed: func() {
			mu.Lock()
			if bySlot[slot] == line {
				delete(bySlot, slot)
			}
			mu.Unlock()
		}}, nil
	}
	argsFor := func(slot int) string {
		mu.Lock()
		defer mu.Unlock()
		return bySlot[slot]
	}
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		line := argsFor(slot)
		youtube := strings.Contains(urls[0], "youtube")
		switch {
		case youtube && strings.Contains(line, "--hostlist="+filepath.Join(lists, zapret.ListYouTube)) && strings.Contains(line, "multidisorder"):
			return zapret.Result{OK: true}
		case !youtube && strings.Contains(line, "--hostlist="+filepath.Join(lists, zapret.ListDiscord)) && strings.Contains(line, "repeats=7:tcp_md5"): // fake-md5-seqovl
			return zapret.Result{OK: true}
		}
		return failed(zapret.KindTLS)
	}
	return c, argsFor
}

func failed(k zapret.Kind) zapret.Result {
	return zapret.Result{Failed: []zapret.Failure{{Host: "www.youtube.com", Kind: k, Text: "нет ответа"}}}
}

func waitZapret(t *testing.T, c *Controller, state string) ZapretView {
	t.Helper()
	for range 400 {
		if v := c.ZapretInfo(); v.Status.State == state {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state %+v, want %s", c.ZapretInfo().Status, state)
	return ZapretView{}
}

func zapretRuleNames(c *Controller) []string {
	var out []string
	for _, r := range c.Settings().Rules {
		if isZapretRule(r) {
			out = append(out, r.Name)
		}
	}
	return out
}

func TestZapretSaveRulesAndPick(t *testing.T) {
	c, _ := zapFixture(t)
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord}}); err != nil {
		t.Fatal(err)
	}
	// The kept rules are at the top: the services go direct, through winws2.
	got := zapretRuleNames(c)
	if !slices.Equal(got, []string{"Обход DPI: YouTube", "Обход DPI: Discord", "Обход DPI: Discord (голос)"}) {
		t.Fatalf("%v", got)
	}
	if rs := c.Settings().Rules; !isZapretRule(rs[0]) || rs[0].Action != rules.Direct {
		t.Fatalf("%+v", rs[0])
	}
	v := waitZapret(t, c, zapret.Running)
	if !strings.Contains(v.CommandLine, "circular") || len(v.Targets) != 3 {
		t.Fatalf("%+v", v)
	}
	// Auto-pick: YouTube opens with fake + disorder, Discord with TCP MD5.
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pick == nil || v.Pick.Running || v.Pick.Results[zapret.YouTube] != "fake-disorder" || v.Pick.Results[zapret.Discord] != "fake-md5-seqovl" {
		t.Fatalf("%+v", v.Pick)
	}
	// The bypass now starts with them (still automatic: circular).
	if !strings.Contains(v.CommandLine, "multidisorder:pos=1,midsld:strategy=1") || v.Targets[0].Picked != "fake-disorder" {
		t.Fatalf("%s\n%+v", v.CommandLine, v.Targets)
	}
	// Kept on disk.
	z, err := c.Store.LoadZapret()
	if err != nil || z.Picked[""].Methods[zapret.Discord] != "fake-md5-seqovl" {
		t.Fatalf("%+v %v", z, err)
	}
	// Off: the rules go, winws2 stops.
	if err := c.SaveZapret(ZapretInput{Enabled: false, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	if n := zapretRuleNames(c); len(n) != 0 {
		t.Fatalf("%v", n)
	}
	waitZapret(t, c, zapret.Off)
}

func TestZapretNotBlocked(t *testing.T) {
	c, _ := zapFixture(t)
	zapretCheckFunc = func(context.Context, int, []string) zapret.Result { return zapret.Result{OK: true} }
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	v, err := c.ZapretPick()
	if err != nil || v.Pick.Results[zapret.YouTube] != zapret.None {
		t.Fatalf("%+v %v", v.Pick, err)
	}
	// Nothing to bypass here: no winws2; the rule stays (direct is right).
	if v.Status.State != zapret.Off || v.CommandLine != "" || v.Targets[0].Using != "не нужен: здесь не блокируется" {
		t.Fatalf("%+v", v)
	}
	if n := zapretRuleNames(c); len(n) != 1 {
		t.Fatalf("%v", n)
	}
}

func TestZapretSitesNeedOne(t *testing.T) {
	c, _ := zapFixture(t)
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}}); err == nil {
		t.Fatal("own sites with none saved")
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}, Sites: []string{"https://Example.org/x"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(c.ZapretLists, zapret.ListSites))
	if !strings.Contains(string(b), "\nexample.org\n") {
		t.Fatalf("%q", b)
	}
	// With its subdomains: a plain name in a rule is that name only.
	if rs := c.Settings().Rules; rs[0].Name != "Обход DPI: Свои сайты" || !slices.Equal(rs[0].Domains, []string{".example.org"}) {
		t.Fatalf("%+v", rs[0])
	}
}

// Picked on a network where nothing is blocked, the bypass does not run
// there; on another network it runs again, and back home it stops.
func TestZapretFollowsNetwork(t *testing.T) {
	c, _ := zapFixture(t)
	quiet, poll := zapretNetQuiet, zapretNetPoll
	t.Cleanup(func() { zapretNetQuiet, zapretNetPoll = quiet, poll })
	zapretNetQuiet, zapretNetPoll = time.Millisecond, time.Hour
	w := &fakeNet{events: make(chan struct{}, 1)}
	w.set(home())
	c.NetWatcher = w
	zapretCheckFunc = func(context.Context, int, []string) zapret.Result { return zapret.Result{OK: true} }
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	if _, watches, _ := w.counts(); watches != 0 {
		t.Fatal("the network is watched before anything depends on it")
	}
	if v, err := c.ZapretPick(); err != nil || v.Status.State != zapret.Off {
		t.Fatalf("%+v %v", v, err)
	}
	w.set(cafe())
	w.events <- struct{}{}
	waitZapret(t, c, zapret.Running)
	w.set(home())
	w.events <- struct{}{}
	waitZapret(t, c, zapret.Off)
	// Off: the watch ends.
	if err := c.SaveZapret(ZapretInput{Enabled: false, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	c.zapretMu.Lock()
	stopped := c.zapretStop == nil
	c.zapretMu.Unlock()
	if !stopped {
		t.Fatal("still watching")
	}
}

func TestTrimPicked(t *testing.T) {
	m := map[string]zapret.Picked{"": {At: time.Unix(1, 0)}}
	for i := range zapret.MaxNetKeys {
		m[string(rune('a'+i))] = zapret.Picked{At: time.Unix(int64(10+i), 0)}
	}
	trimPicked(m)
	if _, ok := m[""]; ok || len(m) != zapret.MaxNetKeys {
		t.Fatalf("%d %v", len(m), ok)
	}
}

// The pick tries every method: the fastest that opens a service goes
// first, the others that open it come next in winws2's rotation.
func TestZapretPickFastestFirst(t *testing.T) {
	c, argsFor := zapFixture(t)
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		switch line := argsFor(slot); {
		case strings.Contains(line, "multidisorder"):
			return zapret.Result{OK: true, Elapsed: 900 * time.Millisecond}
		case strings.Contains(line, "fakedsplit"):
			return zapret.Result{OK: true, Elapsed: 200 * time.Millisecond}
		}
		return failed(zapret.KindFreeze)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	waitZapret(t, c, zapret.Running) // the pick stops this one first
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	// The fastest of the library first, then what the generator made
	// around the fastest two: the same splits with other fakes and
	// foolings (as fast as fakedsplit, they come before fake-disorder).
	ws := v.Pick.Working[zapret.YouTube]
	if v.Pick.Results[zapret.YouTube] != "fakedsplit" || len(ws) != zapretKeep || ws[0] != "fakedsplit" {
		t.Fatalf("%+v", v.Pick)
	}
	for _, id := range ws[1:] {
		if st, ok := zapret.ParseStrategy(id); id != "fake-disorder" && (!ok || st.Split != "fakedsplit" && st.Split != "multidisorder") {
			t.Fatalf("generated %s", id)
		}
	}
	if v.Pick.Tried <= len(zapret.Methods) {
		t.Fatalf("tried %d", v.Pick.Tried)
	}
	// The page names the generated ones and offers them.
	if !slices.ContainsFunc(v.Methods, func(m ZapretMethodView) bool { return m.ID == ws[1] && m.Generated && m.Name != "" }) {
		t.Fatalf("%+v", v.Methods)
	}
	if !strings.Contains(v.CommandLine, "fakedsplit:pos=2:pattern=google_tls:tcp_ts=-1000:tcp_md5:strategy=1") {
		t.Fatalf("%s", v.CommandLine)
	}
	z, _ := c.Store.LoadZapret()
	if !slices.Equal(z.Picked[""].Working[zapret.YouTube], ws) {
		t.Fatalf("%+v", z.Picked)
	}
}

// The pick runs next to the user's bypass: it is not stopped, and the
// diagnosis says how each service is blocked. Blocked by address, a
// service can go through the VPN instead.
func TestZapretPickDiagnosisAndVPN(t *testing.T) {
	c, argsFor := zapFixture(t)
	var mu sync.Mutex
	stopped := false
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		if argsFor(-1) == "" {
			mu.Lock()
			stopped = true // the user's bypass is not running mid-pick
			mu.Unlock()
		}
		if strings.Contains(urls[0], "youtube") {
			if strings.Contains(argsFor(slot), "multidisorder") {
				return zapret.Result{OK: true}
			}
			return failed(zapret.KindFreeze)
		}
		return failed(zapret.KindIP) // Discord: by address, nothing opens it
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord}}); err != nil {
		t.Fatal(err)
	}
	waitZapret(t, c, zapret.Running)
	before := argsFor(-1)
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if stopped {
		t.Fatal("the pick stopped the user's bypass")
	}
	mu.Unlock()
	yd, dd := v.Pick.Diagnosis[zapret.YouTube], v.Pick.Diagnosis[zapret.Discord]
	if yd.Kind != zapret.KindFreeze || !yd.Bypass || dd.Kind != zapret.KindIP || dd.Bypass || dd.Text == "" {
		t.Fatalf("%+v", v.Pick.Diagnosis)
	}
	if v.Pick.Results[zapret.YouTube] != "fake-disorder" || v.Pick.Results[zapret.Discord] != "" {
		t.Fatalf("%+v", v.Pick.Results)
	}
	if argsFor(-1) == before {
		t.Fatal("the bypass did not take the picked method")
	}
	// Discord through the VPN: its rules tunnel, its profiles leave winws2.
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord},
		Methods: map[zapret.Target]string{zapret.Discord: zapret.VPN}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Settings().Rules {
		if strings.HasPrefix(r.Name, ZapretRulePrefix+"Discord") != (r.Action == rules.Tunnel) && isZapretRule(r) {
			t.Fatalf("%+v", r)
		}
	}
	v = waitZapret(t, c, zapret.Running)
	if strings.Contains(v.CommandLine, "discord") || !strings.Contains(v.Targets[1].Using, "VPN") {
		t.Fatalf("%s\n%+v", v.CommandLine, v.Targets[1])
	}
}

// A service sent through the VPN is not picked for.
func TestZapretPickSkipsVPN(t *testing.T) {
	c, _ := zapFixture(t)
	var mu sync.Mutex
	var checked []string
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		mu.Lock()
		checked = append(checked, urls[0])
		mu.Unlock()
		return zapret.Result{OK: true}
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord},
		Methods: map[zapret.Target]string{zapret.Discord: zapret.VPN}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ZapretPick(); err != nil {
		t.Fatal(err)
	}
	for _, u := range checked {
		if strings.Contains(u, "discord") {
			t.Fatalf("checked %s", u)
		}
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Discord},
		Methods: map[zapret.Target]string{zapret.Discord: zapret.VPN}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ZapretPick(); err == nil {
		t.Fatal("a pick with everything through the VPN")
	}
}

// Nothing of the library opens the service: the generator goes over the
// whole space and finds a strategy with one of its own fakes.
func TestZapretGeneratorBroad(t *testing.T) {
	c, argsFor := zapFixture(t)
	seed := zapretSeed
	t.Cleanup(func() { zapretSeed = seed })
	zapretSeed = func() uint64 { return 7 }
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		if strings.Contains(argsFor(slot), "blob=w_") {
			return zapret.Result{OK: true, Elapsed: time.Second}
		}
		return failed(zapret.KindFreeze)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Discord}}); err != nil {
		t.Fatal(err)
	}
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	got := v.Pick.Results[zapret.Discord]
	st, ok := zapret.ParseStrategy(got)
	made := st.Fake
	if !strings.HasPrefix(made, "w_") {
		made = st.Pattern // as the overlap's pattern
	}
	if !ok || !strings.HasPrefix(made, "w_") || len(v.Pick.Working[zapret.Discord]) < 2 {
		t.Fatalf("%+v", v.Pick)
	}
	// winws2 runs it, with its fake.
	if !strings.Contains(v.CommandLine, "--blob="+made+":@") {
		t.Fatalf("%s", v.CommandLine)
	}
	if !slices.ContainsFunc(v.Targets, func(tv ZapretTargetView) bool {
		return tv.Target == zapret.Discord && strings.Contains(tv.Using, st.Name())
	}) {
		t.Fatalf("%+v", v.Targets)
	}
}

// Nothing of the library opens the service: the pick tries Flowseal's
// recipes (zapret.Known) and runs the one that worked, with HyRoute's Lua
// for its fooling.
func TestZapretKnownTried(t *testing.T) {
	c, argsFor := zapFixture(t)
	// hostfakesplit with one repeat, alone and after a fake: the spread makes none.
	known := zapret.Known()
	want := []string{known[5].ID(), known[7].ID()}
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		if strings.Contains(argsFor(slot), "hostfakesplit:host=www.google.com:fool=hyroute_ts:repeats=1:ip_id=zero") {
			return zapret.Result{OK: true, Elapsed: time.Second}
		}
		return failed(zapret.KindTLS)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	ws := slices.Clone(v.Pick.Working[zapret.YouTube])
	slices.Sort(ws)
	slices.Sort(want)
	if got := v.Pick.Results[zapret.YouTube]; !slices.Contains(want, got) || !slices.Equal(ws, want) {
		t.Fatalf("%q %q, want %q: %+v", got, ws, want, v.Pick)
	}
	if !strings.Contains(v.CommandLine, "--lua-init=@"+zapret.LuaFile) || !strings.Contains(v.CommandLine, "fool=hyroute_ts") {
		t.Fatalf("%s", v.CommandLine)
	}
}

// Own sites by address: they get the rule, and an address that is local or
// too wide is refused with its name, not dropped.
func TestZapretSiteAddresses(t *testing.T) {
	c, _ := zapFixture(t)
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}, Sites: []string{"example.org", "192.168.1.0/24"}}); err == nil || !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Fatalf("%v", err)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}, Sites: []string{"162.159.128.1/17", "1.2.3.4"}}); err != nil {
		t.Fatal(err)
	}
	if rs := c.Settings().Rules; rs[0].Name != "Обход DPI: Свои сайты" || !slices.Equal(rs[0].Domains, []string{"162.159.128.0/17", "1.2.3.4"}) || rs[0].Action != rules.Direct {
		t.Fatalf("%+v", rs[0])
	}
	v := waitZapret(t, c, zapret.Running)
	if !strings.Contains(v.CommandLine, "--ipset=sites-ip.txt") {
		t.Fatalf("%s", v.CommandLine)
	}
	// Nothing to pick by: addresses only.
	if _, err := c.ZapretPick(); err == nil {
		t.Fatal("a pick with addresses only")
	}
}

// «Пустить через VPN»: what the user's rules do with the service decides
// the choice; the user's own rule for it is changed, not doubled.
func TestZapretViaVPN(t *testing.T) {
	c, _ := zapFixture(t)
	if _, err := c.ImportURIs("hysteria2://p1@a.example:443#NL\nhysteria2://p2@b.example:443#DE"); err != nil {
		t.Fatal(err)
	}
	var nl, de string
	for _, p := range c.Profiles() {
		if p.Name == "NL" {
			nl = p.ID
		} else {
			de = p.ID
		}
	}
	st := c.Settings()
	st.Rules = []rules.Rule{
		{ID: "yt", Name: "YouTube", Domains: []string{"geosite:youtube", ".youtube.com", ".googlevideo.com"}, Action: rules.Tunnel, Profile: nl},
		{ID: "mix", Name: "Разное", Domains: []string{".discord.com", ".example.org"}, Action: rules.Tunnel, Profile: de},
	}
	st.DefaultAction = rules.Direct
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord}}); err != nil {
		t.Fatal(err)
	}
	r, err := c.ZapretRoute(zapret.YouTube)
	if err != nil || len(r.By) == 0 || r.By[0].ID != "yt" || !r.By[0].Own || r.By[0].Route != "через «NL»" {
		t.Fatalf("%+v %v", r, err)
	}
	// youtube.com goes by «YouTube», the rest of the list by default.
	if r.Tunnel || r.By[len(r.By)-1].ID != "" || r.By[len(r.By)-1].Name != "Всё остальное" {
		t.Fatalf("%+v", r)
	}
	d, _ := c.ZapretRoute(zapret.Discord)
	if d.By[0].ID != "mix" || d.By[0].Own {
		t.Fatalf("not its own: %+v", d.By)
	}

	// Through DE, changing the user's «YouTube»: it takes youtube.com and
	// googlevideo.com only, so the bypass's rule takes the rest of the
	// service through DE too.
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.YouTube, Via: de, EditRule: "yt"}); err != nil {
		t.Fatal(err)
	}
	rs := c.Settings().Rules
	names := func(rs []rules.Rule) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	if names(rs) != "Обход DPI: YouTube,Обход DPI: Discord,Обход DPI: Discord (голос),YouTube,Разное" ||
		rs[0].Action != rules.Tunnel || rs[0].Profile != de || rs[3].Profile != de {
		t.Fatalf("%s %+v %+v", names(rs), rs[0], rs[3])
	}
	if v := c.ZapretInfo(); v.Settings.Via[zapret.YouTube] != de || v.Targets[0].Using != "через «DE», без обхода" {
		t.Fatalf("%+v %q", v.Settings.Via, v.Targets[0].Using)
	}
	// By the user's rules only when they take all of it.
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.YouTube, Via: zapret.ViaRules}); err == nil {
		t.Fatal("by rules that leave sites of it direct")
	}
	// A rule that is not only about the service is never changed.
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.Discord, Via: nl, EditRule: "mix"}); err == nil {
		t.Fatal("changed a shared rule")
	}
	// Discord through NL by a rule of the bypass's: one rule, with it.
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.Discord, Via: nl}); err != nil {
		t.Fatal(err)
	}
	rs = c.Settings().Rules
	if rs[1].Name != "Обход DPI: Discord" || rs[1].Action != rules.Tunnel || rs[1].Profile != nl || rs[2].Profile != nl || len(rs) != 5 {
		t.Fatalf("%+v", rs[:3])
	}
	if v := c.ZapretInfo(); v.Targets[1].Using != "через «NL», без обхода" {
		t.Fatalf("%q", v.Targets[1].Using)
	}
	// Back to the bypass: direct again, the choice forgotten.
	in := ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord}, Methods: map[zapret.Target]string{zapret.YouTube: zapret.VPN}}
	if err := c.SaveZapret(in); err != nil {
		t.Fatal(err)
	}
	if v := c.ZapretInfo(); v.Settings.Via[zapret.Discord] != "" || v.Settings.Via[zapret.YouTube] != de {
		t.Fatalf("%+v", v.Settings.Via)
	}
	if rs = c.Settings().Rules; rs[1].Name != "Обход DPI: Discord" || rs[1].Action != rules.Direct || rs[1].Profile != "" {
		t.Fatalf("%+v", rs[1])
	}
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.YouTube, Via: "nope"}); err == nil {
		t.Fatal("an unknown server")
	}
}

// By the user's rules: only for rules that take every site of the
// service through the VPN, a name under each too; Discord's voice keeps a
// rule of the bypass's through the main server; addresses are never
// left to the rules.
func TestZapretViaRules(t *testing.T) {
	c, _ := zapFixture(t)
	if _, err := c.ImportURIs("hysteria2://p1@a.example:443#NL"); err != nil {
		t.Fatal(err)
	}
	nl := c.Profiles()[0].ID
	st := c.Settings()
	st.Rules = []rules.Rule{
		{ID: "yt", Name: "YouTube", Domains: zapretRuleSites(zapret.YouTube, nil), Action: rules.Tunnel, Profile: nl},
		{ID: "dc", Name: "Discord", Domains: zapretRuleSites(zapret.Discord, nil), Action: rules.Tunnel, Profile: nl},
		{ID: "own", Name: "Сайт", Domains: []string{"example.org"}, Action: rules.Tunnel, Profile: nl},
	}
	st.DefaultAction = rules.Direct
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube, zapret.Discord, zapret.Sites},
		Sites: []string{"example.org", "203.0.113.7"}}); err != nil {
		t.Fatal(err)
	}
	if r, err := c.ZapretRoute(zapret.YouTube); err != nil || !r.Tunnel {
		t.Fatalf("%+v %v", r, err)
	}
	// «example.org» alone takes the name, not the names under it, and
	// the address is not asked.
	r, _ := c.ZapretRoute(zapret.Sites)
	if r.Tunnel || !slices.ContainsFunc(r.By, func(b ZapretRouteRule) bool { return slices.Contains(b.Sites, "*.example.org") }) {
		t.Fatalf("%+v", r)
	}
	if err := c.ZapretViaVPN(ZapretViaInput{Target: zapret.Sites, Via: zapret.ViaRules}); err == nil {
		t.Fatal("own sites left to rules that miss them")
	}
	for _, tg := range []zapret.Target{zapret.YouTube, zapret.Discord} {
		if err := c.ZapretViaVPN(ZapretViaInput{Target: tg, Via: zapret.ViaRules}); err != nil {
			t.Fatal(tg, err)
		}
	}
	var got []string
	for _, r := range c.Settings().Rules {
		if isZapretRule(r) {
			got = append(got, r.Name)
			if r.Name == "Обход DPI: Discord (голос)" && (r.Action != rules.Tunnel || r.Profile != "") {
				t.Errorf("voice %+v", r)
			}
		}
	}
	if !slices.Equal(got, []string{"Обход DPI: Discord (голос)", "Обход DPI: Свои сайты"}) {
		t.Fatalf("%q", got)
	}
}

// Self-healing: a first pick on a new network by itself; a method that
// stops opening YouTube is replaced by a pick of its own; a network that
// is down is left alone.
func TestZapretHeal(t *testing.T) {
	c, argsFor := zapFixture(t)
	first, every, again, gap := zapretHealFirst, zapretHealEvery, zapretHealAgain, zapretHealGap
	t.Cleanup(func() {
		c.stopHeal()
		zapretHealFirst, zapretHealEvery, zapretHealAgain, zapretHealGap = first, every, again, gap
	})
	zapretHealFirst, zapretHealEvery, zapretHealAgain = 10*time.Millisecond, 30*time.Millisecond, 5*time.Millisecond
	zapretHealGap = 0
	base := zapretCheckFunc
	var mode atomic.Int32 // 0 as the fixture, 1 YouTube needs hostfakesplit, 2 the network is down
	firstIs := func(line, m string) bool {
		for _, a := range strings.Fields(line) {
			if strings.HasSuffix(a, ":strategy=1") && strings.Contains(a, m) {
				return true
			}
		}
		return false
	}
	var liveChecks atomic.Int32
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		if slot == zapret.Live {
			liveChecks.Add(1)
		}
		switch mode.Load() {
		case 2:
			return failed(zapret.KindDNS)
		case 1:
			line := argsFor(slot)
			if slot == zapret.Live && firstIs(line, "hostfakesplit") || slot > 0 && strings.Contains(line, "hostfakesplit") {
				return zapret.Result{OK: true}
			}
			return failed(zapret.KindTLS)
		}
		return base(ctx, slot, urls)
	}
	picked := func() string {
		c.zapretMu.Lock()
		defer c.zapretMu.Unlock()
		for _, pk := range c.zapretCfg.Picked { // one network
			return pk.Methods[zapret.YouTube]
		}
		return ""
	}
	wait := func(what string, ok func() bool) {
		t.Helper()
		for range 2000 {
			if ok() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s: %+v", what, c.ZapretInfo().HealNote)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	// No pick on this network yet: one by itself.
	wait("the first pick", func() bool { return picked() != "" && !strings.Contains(picked(), "hostfakesplit") })
	if v := c.ZapretInfo(); v.Pick == nil || !v.Pick.Auto || !strings.Contains(v.Pick.Why, "ещё не подбирали") {
		t.Fatalf("%+v", v.Pick)
	}
	wait("a check", func() bool { return strings.HasPrefix(c.ZapretInfo().HealNote, "Проверено") })

	// The method stops working: picked again, by itself.
	mode.Store(1)
	wait("the new pick", func() bool { return strings.Contains(picked(), "hostfakesplit") })
	wait("the note", func() bool { return strings.Contains(c.ZapretInfo().HealNote, "подобрал заново") })
	if v := c.ZapretInfo(); !strings.Contains(v.Pick.Why, "YouTube перестал открываться через обход (www.youtube.com: нет ответа)") {
		t.Fatalf("%+v", v.Pick)
	}

	// Down: no pick, a note.
	mode.Store(2)
	wait("down", func() bool {
		return strings.Contains(c.ZapretInfo().HealNote, "не открывается и без обхода")
	})
	if !strings.Contains(picked(), "hostfakesplit") {
		t.Fatal(picked())
	}

	// Switched off: no more checks.
	off := false
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}, AutoHeal: &off}); err != nil {
		t.Fatal(err)
	}
	if c.ZapretInfo().Settings.Heals() {
		t.Fatal("still on")
	}
	n := liveChecks.Load()
	time.Sleep(150 * time.Millisecond)
	if liveChecks.Load() > n+2 { // one may have been under way
		t.Fatalf("%d checks after off", liveChecks.Load()-n)
	}
}

// Self-healing waits between picks on a network.
func TestZapretHealGap(t *testing.T) {
	c, _ := zapFixture(t)
	c.pickMu.Lock()
	c.autoPicks = map[string]autoPick{"": {at: time.Now(), found: false}}
	c.pickMu.Unlock()
	c.healPick(context.Background(), "", time.Now(), "YouTube перестал открываться", []zapret.Target{zapret.YouTube})
	if v := c.ZapretInfo(); v.Pick != nil || !strings.Contains(v.HealNote, "подбирал недавно") {
		t.Fatalf("%+v %q", v.Pick, v.HealNote)
	}
}

// A pick that ran after the round began (the user's «Подобрать») is not
// followed by one of self-healing's.
func TestZapretHealAfterUserPick(t *testing.T) {
	c, _ := zapFixture(t)
	started := time.Now().Add(-time.Minute)
	c.zapretMu.Lock()
	c.zapretCfg.Picked = map[string]zapret.Picked{"": {At: time.Now(), Methods: map[zapret.Target]string{}}}
	c.zapretMu.Unlock()
	c.healPick(context.Background(), "", started, "YouTube перестал открываться", []zapret.Target{zapret.YouTube})
	c.pickMu.Lock()
	_, picked := c.autoPicks[""]
	c.pickMu.Unlock()
	if v := c.ZapretInfo(); v.Pick != nil || picked {
		t.Fatalf("picked again: %+v %v", v.Pick, picked)
	}
}

// A dead own site (no such name) is left out of the pick, not let fail
// the others; the checks after it leave it out too.
func TestZapretPickSkipsDeadSite(t *testing.T) {
	c, argsFor := zapFixture(t)
	zapretCheckFunc = func(ctx context.Context, slot int, urls []string) zapret.Result {
		var r zapret.Result
		for _, u := range urls {
			host := strings.TrimSuffix(strings.TrimPrefix(u, "https://"), "/")
			switch {
			case host == "dead.example":
				r.Failed = append(r.Failed, zapret.Failure{Host: host, Kind: zapret.KindDNS, Text: "имя не найдено"})
			case slot == 0 || !strings.Contains(argsFor(slot), "multidisorder"):
				r.Failed = append(r.Failed, zapret.Failure{Host: host, Kind: zapret.KindTLS, Text: "сброс"})
			}
		}
		r.OK = len(r.Failed) == 0 && len(urls) > 0
		return r
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}, Sites: []string{"dead.example", "example.org"}}); err != nil {
		t.Fatal(err)
	}
	v, err := c.ZapretPick()
	if err != nil || v.Pick.Results[zapret.Sites] == "" || len(v.Pick.Skipped) != 1 || !strings.Contains(v.Pick.Skipped[0], "dead.example") {
		t.Fatalf("%v %+v", err, v.Pick)
	}
	for _, pk := range v.Settings.Picked {
		if !slices.Equal(pk.SkippedSites, []string{"dead.example"}) {
			t.Fatalf("%+v", pk)
		}
	}
	// All of them dead: the diagnosis says so, as before.
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Sites}, Sites: []string{"dead.example"}}); err != nil {
		t.Fatal(err)
	}
	v, _ = c.ZapretPick()
	if v.Pick.Results[zapret.Sites] != "" || len(v.Pick.Skipped) != 0 || v.Pick.Diagnosis[zapret.Sites].Kind != zapret.KindDNS {
		t.Fatalf("%+v", v.Pick)
	}
}

// Testers slow to start (a busy or just woken computer) are waited for;
// ones that never start are named so, not with an empty reason.
func TestZapretPickSlowTesters(t *testing.T) {
	c, _ := zapFixture(t)
	spawn, wait := zapretSpawn, zapretStartWait
	t.Cleanup(func() { zapretStartWait = wait })
	var delay atomic.Int64
	delay.Store(int64(50 * time.Millisecond))
	zapretSpawn = func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) {
		if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--wf-raw-filter=("+zapret.ProbeExclude()+")") }) {
			time.Sleep(time.Duration(delay.Load())) // a tester
		}
		return spawn(exe, args, env, out)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	if v, err := c.ZapretPick(); err != nil || v.Pick.Results[zapret.YouTube] == "" {
		t.Fatalf("%v %+v", err, v.Pick)
	}
	zapretStartWait = 20 * time.Millisecond
	delay.Store(int64(300 * time.Millisecond))
	_, err := c.ZapretPick()
	if err == nil || !strings.Contains(err.Error(), "не успел запуститься") {
		t.Fatalf("%v", err)
	}
}

// YouTube's checks take the video servers the browser reached lately,
// newest first, one per cluster; from memory only.
func TestZapretVideoChecks(t *testing.T) {
	c, _ := newCtl(t)
	if got := c.zapretChecks(zapret.YouTube, nil, nil); !slices.Equal(got, zapret.Checks(zapret.YouTube, nil)) {
		t.Fatalf("no connections: %q", got)
	}
	reg := flows.NewRegistry(8)
	t0 := time.Now()
	for i, d := range []string{"rr1---sn-old1-aa.googlevideo.com", "www.youtube.com", "rr4---sn-aj5go5-5i.c.youtube.com,rr4.sn-aj5go5-5i.c.youtube.com", "r2---sn-gvnuxaxjvh-jx3s.googlevideo.com"} {
		r := reg.Open(&flows.Record{Proto: 6, Dst: netip.MustParseAddrPort("192.0.2.1:443"), Start: t0.Add(time.Duration(i) * time.Second)})
		r.Set(func(f *flows.Fields) { f.Domain = d })
		if i == 0 {
			reg.Close(r, t0.Add(time.Minute))
		}
	}
	c.mu.Lock()
	c.lastFlows = reg
	c.mu.Unlock()
	got := c.zapretChecks(zapret.YouTube, nil, nil)
	want := append(zapret.Checks(zapret.YouTube, nil), "https://r2---sn-gvnuxaxjvh-jx3s.googlevideo.com/generate_204", "https://rr4---sn-aj5go5-5i.c.youtube.com/generate_204")
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if got := c.zapretChecks(zapret.Discord, nil, nil); !slices.Equal(got, zapret.Checks(zapret.Discord, nil)) {
		t.Fatalf("%q", got)
	}
}
