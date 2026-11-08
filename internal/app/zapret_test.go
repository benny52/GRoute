package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// zapFixture: winws2 never really runs; the checks see which method the
// last started winws2 had.
func zapFixture(t *testing.T) (*Controller, *[]string) {
	t.Helper()
	c, _ := newCtl(t)
	lists := t.TempDir()
	c.ZapretLists = lists
	c.ZapretPrepare = func(context.Context) (string, error) { return t.TempDir(), nil }
	var mu sync.Mutex
	var lastArgs []string
	spawn, settle, check := zapretSpawn, zapretSettle, zapretCheckFunc
	t.Cleanup(func() { zapretSpawn, zapretSettle, zapretCheckFunc = spawn, settle, check })
	zapretSettle = time.Millisecond
	zapretSpawn = func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) {
		mu.Lock()
		lastArgs = slices.Clone(args)
		mu.Unlock()
		// Stopped, it no longer helps the checks.
		return &zapChild{done: make(chan struct{}), killed: func() { mu.Lock(); lastArgs = nil; mu.Unlock() }}, nil
	}
	var started []string
	zapretCheckFunc = func(ctx context.Context, urls []string) zapret.Result {
		mu.Lock()
		line := strings.Join(lastArgs, " ")
		mu.Unlock()
		youtube := strings.Contains(urls[0], "youtube")
		switch {
		case youtube && strings.Contains(line, "--hostlist="+filepath.Join(lists, zapret.ListYouTube)) && strings.Contains(line, "multidisorder"):
			return zapret.Result{OK: true}
		case !youtube && strings.Contains(line, "--hostlist="+filepath.Join(lists, zapret.ListDiscord)) && strings.Contains(line, "tcp_md5"):
			return zapret.Result{OK: true}
		}
		return zapret.Result{Failed: []string{urls[0] + ": нет ответа"}}
	}
	return c, &started
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
	zapretCheckFunc = func(context.Context, []string) zapret.Result { return zapret.Result{OK: true} }
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
	if rs := c.Settings().Rules; rs[0].Name != "Обход DPI: Свои сайты" || !slices.Equal(rs[0].Domains, []string{"example.org"}) {
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
	zapretCheckFunc = func(context.Context, []string) zapret.Result { return zapret.Result{OK: true} }
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
	c, _ := zapFixture(t)
	var mu sync.Mutex
	var last []string
	spawn := zapretSpawn
	zapretSpawn = func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) {
		mu.Lock()
		last = slices.Clone(args)
		mu.Unlock()
		return spawn(exe, args, env, out)
	}
	zapretCheckFunc = func(ctx context.Context, urls []string) zapret.Result {
		mu.Lock()
		line := strings.Join(last, " ")
		mu.Unlock()
		switch {
		case !strings.Contains(line, "--lua-desync="):
			return zapret.Result{Failed: []string{"www.youtube.com: нет ответа"}} // no bypass
		case strings.Contains(line, "multidisorder"):
			return zapret.Result{OK: true, Elapsed: 900 * time.Millisecond}
		case strings.Contains(line, "fakedsplit"):
			return zapret.Result{OK: true, Elapsed: 200 * time.Millisecond}
		}
		return zapret.Result{Failed: []string{"www.youtube.com: нет ответа"}}
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	v, err := c.ZapretPick()
	if err != nil {
		t.Fatal(err)
	}
	if v.Pick.Results[zapret.YouTube] != "fakedsplit" || !slices.Equal(v.Pick.Working[zapret.YouTube], []string{"fakedsplit", "fake-disorder"}) {
		t.Fatalf("%+v", v.Pick)
	}
	if !strings.Contains(v.CommandLine, "fakedsplit:blob=google_tls:pos=2:strategy=1") || !strings.Contains(v.CommandLine, "multidisorder:pos=1,midsld:strategy=2") {
		t.Fatalf("%s", v.CommandLine)
	}
	z, _ := c.Store.LoadZapret()
	if !slices.Equal(z.Picked[""].Working[zapret.YouTube], []string{"fakedsplit", "fake-disorder"}) {
		t.Fatalf("%+v", z.Picked)
	}
}
