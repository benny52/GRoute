package zapret

import (
	"errors"
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

	"github.com/lardan099/hyroute/internal/hysteria"
)

func TestPlanFor(t *testing.T) {
	s := Settings{Enabled: true, Targets: []Target{YouTube, Discord},
		Methods: map[Target]string{Discord: "fake"},
		Picked:  map[string]Picked{"home": {Methods: map[Target]string{YouTube: "seqovl"}}}}
	p, ok := s.PlanFor(Discord, "home")
	if !ok || p.Circular || !slices.Equal(p.Methods, []string{"fake"}) {
		t.Fatalf("fixed: %+v", p)
	}
	p, ok = s.PlanFor(YouTube, "home")
	if !ok || !p.Circular || p.Methods[0] != "seqovl" || len(p.Methods) != len(Methods) {
		t.Fatalf("picked first: %+v", p)
	}
	p, _ = s.PlanFor(YouTube, "elsewhere")
	if p.Methods[0] != Methods[0].ID {
		t.Fatalf("no pick: %+v", p)
	}
	// Every method that worked here, fastest first, then the rest.
	pk := s.Picked["home"]
	pk.Working = map[Target][]string{YouTube: {"seqovl", "fake", "fakedsplit"}}
	s.Picked["home"] = pk
	p, _ = s.PlanFor(YouTube, "home")
	if !slices.Equal(p.Methods[:3], []string{"seqovl", "fake", "fakedsplit"}) || len(p.Methods) != len(Methods) {
		t.Fatalf("working first: %+v", p)
	}
	// An ID this build does not know is dropped on load.
	pk.Methods[Discord] = "gone"
	pk.Working[Discord] = []string{"gone", "fake"}
	s.Normalize()
	if _, ok := s.Picked["home"].Methods[Discord]; ok || !slices.Equal(s.Picked["home"].Working[Discord], []string{"fake"}) {
		t.Fatalf("%+v", s.Picked["home"])
	}
	s.Picked["home"].Methods[YouTube] = None
	if _, ok := s.PlanFor(YouTube, "home"); ok {
		t.Fatal("not blocked here, still a plan")
	}
}

func TestNormalize(t *testing.T) {
	s := Settings{Targets: []Target{"telegram", YouTube, YouTube}, Sites: []string{" https://WWW.Example.com/x ", "example.com", "bad site", "x"},
		Methods: map[Target]string{YouTube: "nope", Discord: None}}
	s.Normalize()
	if !slices.Equal(s.Targets, []Target{YouTube}) || !slices.Equal(s.Sites, []string{"www.example.com", "example.com"}) ||
		len(s.Methods) != 1 || s.Methods[Discord] != None {
		t.Fatalf("%+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBuild(t *testing.T) {
	dir, lists := filepath.FromSlash("/z/winws2"), filepath.FromSlash("/data/zapret")
	if !filepath.IsAbs(dir) {
		dir, lists = `C:\z\winws2`, `C:\data\zapret`
	}
	s := Settings{Enabled: true, Targets: []Target{YouTube, Discord}, Methods: map[Target]string{YouTube: "fake"}}
	plans := map[Target]Plan{}
	for _, tg := range s.Targets {
		if p, ok := s.PlanFor(tg, ""); ok {
			plans[tg] = p
		}
	}
	args, err := Build(BuildConfig{Dir: dir, Lists: lists, Plans: plans})
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{
		"--wf-tcp-out=80,443," + discordMediaTCP, "--wf-udp-out=443," + discordVoiceUDP, "--wf-tcp-in=80,443",
		"zapret-auto.lua", "--blob=google_tls:@", "--blob=vk_tls:@", "--filter-l7=discord,stun",
		// circular before the payload filter, seeing every packet; the
		// methods only the ClientHello.
		"--in-range=-s5556 --lua-desync=hyroute_circular:target=discord:fails=3:retrans=2:nld=2 --in-range=x --payload=tls_client_hello --lua-desync=",
		// QUIC's acknowledgements stay out of winws2; inbound TCP is not
		// narrowed (a filter on bytes reorders a stream).
		"--wf-raw-filter=" + quicLean + " ",
		"hostfakesplit:host=discord.com:tcp_ts=-1000:tcp_md5:strategy=8", "--lua-desync=fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7 ",
	} {
		if !strings.Contains(line+" ", want) {
			t.Errorf("no %q in\n%s", want, CommandLine(args))
		}
	}
	// Every profile skips HyRoute's servers; profiles are separated by --new.
	if n, m := strings.Count(line, "--ipset-exclude="), strings.Count(line, "--new"); n != m+1 || n != 6 {
		t.Fatalf("%d excludes, %d --new", n, m)
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--lua-init=") && !strings.HasPrefix(a, "--lua-init=@") {
			t.Fatalf("inline Lua: %s", a)
		}
	}
	if _, err := Build(BuildConfig{Dir: dir, Lists: lists}); err == nil {
		t.Fatal("no targets built")
	}
	// Own sites count failures per host: nld=2 of example.co.uk is co.uk.
	sp, _ := Settings{Enabled: true, Targets: []Target{Sites}}.PlanFor(Sites, "")
	sargs, err := Build(BuildConfig{Dir: dir, Lists: lists, Plans: map[Target]Plan{Sites: sp}})
	if sl := strings.Join(sargs, " "); err != nil || strings.Contains(sl, "nld") || !strings.Contains(sl, "hyroute_circular:target=sites:fails=3:retrans=2 --in-range=x") {
		t.Fatalf("%v %s", err, sl)
	}
	if strings.Contains(line, "Payload[0] == 0x16") || strings.Contains(line, "success_detector") {
		t.Fatalf("inbound TCP narrowed by its bytes: %s", line)
	}
	// YouTube's video servers keyed by cluster: HyRoute's Lua, loaded;
	// the other targets keep the standard key.
	if !strings.Contains(line, "--lua-init=@"+filepath.Join(lists, LuaFile)) || strings.Contains(line, "hostkey=") {
		t.Fatalf("%s", CommandLine(args))
	}
	yp, _ := Settings{Enabled: true, Targets: []Target{YouTube}}.PlanFor(YouTube, "")
	yargs, _ := Build(BuildConfig{Dir: dir, Lists: lists, Plans: map[Target]Plan{YouTube: yp, Discord: yp}})
	if yl := strings.Join(yargs, " "); !strings.Contains(yl, "hyroute_circular:target=youtube:fails=3:retrans=2:nld=2:hostkey=hyroute_hostkey ") || strings.Count(yl, "hostkey=") != 1 {
		t.Fatalf("%s", CommandLine(yargs))
	}
	// A single method: no orchestrator; the slots' filter goes with QUIC's.
	one, _ := Build(BuildConfig{Dir: dir, Lists: lists, Filter: ProbeOnly(1), Plans: map[Target]Plan{YouTube: {Methods: []string{"fake"}}}})
	if ol := strings.Join(one, " "); strings.Contains(ol, "--wf-tcp-in") || strings.Contains(ol, LuaFile) || !strings.Contains(ol, "--wf-raw-filter=("+ProbeOnly(1)+") and "+quicLean+" ") {
		t.Fatalf("%s", ol)
	}
	cl := CommandLine(args)
	if strings.Contains(cl, "data") || !strings.Contains(cl, "--blob=google_tls:@tls_clienthello_www_google_com.bin") {
		t.Fatalf("%s", cl)
	}
}

func TestWriteLists(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLists(dir, nil, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")}, nil); err != nil {
		t.Fatal(err)
	}
	if l, err := os.ReadFile(filepath.Join(dir, LuaFile)); err != nil || !strings.Contains(string(l), "function hyroute_hostkey(desync)") ||
		!strings.Contains(string(l), "function hyroute_circular(ctx, desync)") || !strings.Contains(string(l), `io.stdout:write("HYROUTE\tswitch\t"`) {
		t.Fatalf("%v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ListSites))
	if !strings.Contains(string(b), "example.invalid") {
		t.Fatalf("an empty sites list must not match every host: %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, ListExcluded))
	if strings.Count(string(b), "192.0.2.1") != 1 {
		t.Fatalf("%q", b)
	}
	b, _ = os.ReadFile(filepath.Join(dir, ListDiscord))
	if !strings.Contains(string(b), "\ndiscord.media\n") || !strings.Contains(string(b), "\ncloudflare-ech.com\n") ||
		!strings.Contains(string(b), "\ndiscord-attachments-uploads-prd.storage.googleapis.com\n") {
		t.Fatalf("%q", b)
	}
	// ECH's outer name is winws2's only: as a rule it would send every
	// Cloudflare site with ECH direct.
	if slices.Contains(Domains(Discord, nil), "cloudflare-ech.com") {
		t.Fatal("cloudflare-ech.com in Discord's rule")
	}
	// HyRoute's own hosts in a target's list: the sites list stops being
	// the placeholder.
	if err := WriteLists(dir, nil, nil, map[Target][]string{Sites: {"cf.example"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ListSites)); string(b) != "# HyRoute: файл пересоздаётся\ncf.example\n" {
		t.Fatalf("%q", b)
	}
}

func TestNormalizeWorkers(t *testing.T) {
	got := NormalizeWorkers([]string{"https://My-Worker.User.workers.dev/apiws", "my-worker.user.workers.dev", "1.2.3.4", "10.0.0.0/8", "nodot", "",
		"a.dev", "b.dev", "c.dev", "d.dev", "e.dev"})
	if !slices.Equal(got, []string{"my-worker.user.workers.dev", "a.dev", "b.dev", "c.dev", "d.dev"}) {
		t.Fatalf("%q", got)
	}
}

func TestShowCommandLine(t *testing.T) {
	if os.Getenv("ZAPRET_SHOW") == "" {
		t.Skip()
	}
	args, _ := Build(BuildConfig{Dir: `/r/zapret`, Lists: `/d/zapret`, Plans: map[Target]Plan{YouTube: {Methods: []string{"fake-seqovl"}}, Discord: {Methods: []string{"fake", "seqovl"}, Circular: true}}})
	t.Log("\n" + CommandLine(args))
}

type fakeChild struct{ done chan struct{} }

func (f *fakeChild) Wait() error { <-f.done; return errors.New("exit status 1") }
func (f *fakeChild) Kill() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return nil
}

func TestRunner(t *testing.T) {
	starts := make(chan *fakeChild, 4)
	r := &Runner{Exe: "winws2.exe"}
	r.Spawn = func(exe string, args, env []string, out io.Writer) (hysteria.Child, error) {
		out.Write([]byte("windivert initialized\nerror: cannot open hostlist\n"))
		c := &fakeChild{done: make(chan struct{})}
		starts <- c
		return c, nil
	}
	r.Start([]string{"--x"})
	c := <-starts
	waitState := func(want string) Status {
		for range 200 {
			if st := r.Status(); st.State == want {
				return st
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("state %+v, want %s", r.Status(), want)
		return Status{}
	}
	waitState(Running)
	c.Kill() // it exits on its own
	st := waitState(Failed)
	if !strings.Contains(st.Error, "cannot open hostlist") || st.Restarts != 1 {
		t.Fatalf("%+v", st)
	}
	select {
	case <-starts: // started again after the backoff
	case <-time.After(5 * time.Second):
		t.Fatal("not restarted")
	}
	r.Stop()
	if st := r.Status(); st.State != Off {
		t.Fatalf("%+v", st)
	}
}

// slowChild exits a while after Kill, as a real process does.
type slowChild struct {
	done chan struct{}
	once sync.Once
	gone atomic.Bool
}

func (c *slowChild) Wait() error { <-c.done; return nil }
func (c *slowChild) Kill() error {
	c.once.Do(func() {
		go func() {
			time.Sleep(30 * time.Millisecond)
			c.gone.Store(true)
			close(c.done)
		}()
	})
	return nil
}

// A new winws2 starts only once the old one is gone: winws2 refuses to
// run next to a copy with the same filter.
func TestRunnerWaitsForExit(t *testing.T) {
	var mu sync.Mutex
	var last *slowChild
	overlap := false
	r := &Runner{Exe: "winws2.exe", Spawn: func(string, []string, []string, io.Writer) (hysteria.Child, error) {
		mu.Lock()
		defer mu.Unlock()
		if last != nil && !last.gone.Load() {
			overlap = true
		}
		last = &slowChild{done: make(chan struct{})}
		return last, nil
	}}
	running := func() {
		for range 400 {
			if r.Status().State == Running {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("not running")
	}
	r.Start([]string{"--a"})
	running()
	r.Start([]string{"--b"})
	running()
	r.Stop()
	mu.Lock()
	defer mu.Unlock()
	if overlap || !last.gone.Load() {
		t.Fatalf("overlap %v, last gone %v", overlap, last.gone.Load())
	}
}

// A winws2 that did not initialize (0xC0000142) starts again at once, not
// after the backoff: a pick's tester would otherwise count as not working.
func TestRunnerRetriesInit(t *testing.T) {
	old := dllInitFailed
	t.Cleanup(func() { dllInitFailed = old })
	errInit := errors.New("exit status 0xc0000142")
	dllInitFailed = func(err error) bool { return err == errInit }
	var mu sync.Mutex
	starts := 0
	r := &Runner{Exe: "winws2.exe", Spawn: func(string, []string, []string, io.Writer) (hysteria.Child, error) {
		mu.Lock()
		defer mu.Unlock()
		starts++
		if starts <= 2 {
			return initFails{errInit}, nil
		}
		return &fakeChild{done: make(chan struct{})}, nil
	}}
	r.Start([]string{"--x"})
	defer r.Stop()
	deadline := time.Now().Add(1500 * time.Millisecond) // well under the 2 s backoff
	for time.Now().Before(deadline) {
		mu.Lock()
		n := starts
		mu.Unlock()
		if st := r.Status(); n == 3 && st.State == Running && st.Restarts == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("starts %d, %+v", starts, r.Status())
}

type initFails struct{ err error }

func (f initFails) Wait() error { return f.err }
func (f initFails) Kill() error { return nil }

func TestSiteAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4": "1.2.3.4", "https://1.2.3.4/x": "1.2.3.4", "1.2.3.4:443": "1.2.3.4",
		"104.16.1.0/13": "104.16.0.0/13", " 162.159.128.0/17 ": "162.159.128.0/17", "5.6.7.8/32": "5.6.7.8",
		"[2606:4700::1]:443": "2606:4700::1", "2606:4700::/32": "2606:4700::/32", "::ffff:1.2.3.4": "1.2.3.4",
		"Example.com": "example.com", "https://www.Example.com:8443/x": "www.example.com",
		// Local, reserved or too wide: never.
		"10.0.0.1": "", "192.168.1.0/24": "", "127.0.0.1": "", "8.0.0.0/7": "", "172.0.0.0/8": "",
		"100.64.1.1": "", "::1": "", "fe80::1": "", "2000::/15": "", "0.0.0.0/0": "", "224.0.0.1": "",
		"1.2.3": "", "1.2.3.400": "", "1.2.3.4/33": "", "fe80::1%eth0": "",
	} {
		if got := NormalizeSite(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	sites := []string{"example.org", "1.2.3.4", "104.16.0.0/13"}
	if n, a := SiteNames(sites), SiteNets(sites); !slices.Equal(n, []string{"example.org"}) || !slices.Equal(a, []string{"1.2.3.4", "104.16.0.0/13"}) {
		t.Fatalf("%v %v", n, a)
	}
	s := Settings{Enabled: true, Targets: []Target{Sites}, Sites: sites}
	s.Normalize()
	if err := s.Validate(); err != nil || len(s.Sites) != 3 {
		t.Fatalf("%v %v", err, s.Sites)
	}
	// Lists: names by name, addresses as an ipset.
	dir := t.TempDir()
	if err := WriteLists(dir, sites, nil, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ListSites))
	ib, _ := os.ReadFile(filepath.Join(dir, ListSitesNet))
	if !strings.Contains(string(b), "\nexample.org\n") || strings.Contains(string(b), "1.2.3.4") ||
		!strings.Contains(string(ib), "\n1.2.3.4\n104.16.0.0/13\n") {
		t.Fatalf("%q\n%q", b, ib)
	}
	// Profiles: by name and by address; only addresses, no name profile.
	bin, lists := filepath.FromSlash("/z"), filepath.FromSlash("/l")
	if !filepath.IsAbs(bin) {
		bin, lists = `C:\z`, `C:\l`
	}
	plans := map[Target]Plan{Sites: {Methods: []string{"fake"}}}
	args, err := Build(BuildConfig{Dir: bin, Lists: lists, Plans: plans, Sites: sites})
	line := strings.Join(args, " ")
	if err != nil || !strings.Contains(line, "--hostlist="+filepath.Join(lists, ListSites)) || !strings.Contains(line, "--ipset="+filepath.Join(lists, ListSitesNet)) {
		t.Fatalf("%v\n%s", err, line)
	}
	args, _ = Build(BuildConfig{Dir: bin, Lists: lists, Plans: plans, Sites: []string{"1.2.3.4"}})
	if line := strings.Join(args, " "); strings.Contains(line, ListSites+" ") || !strings.Contains(line, "--comment=Свои адреса") {
		t.Fatalf("%s", line)
	}
	// The checks: names only.
	if c := Checks(Sites, sites); !slices.Equal(c, []string{"https://example.org/"}) {
		t.Fatalf("%v", c)
	}
	if c := Checks(Sites, []string{"1.2.3.4"}); len(c) != 0 {
		t.Fatalf("%v", c)
	}
}

func TestVideoServer(t *testing.T) {
	for _, c := range []struct {
		host, cluster string
	}{
		{"rr4---sn-aj5go5-5i.googlevideo.com", "aj5go5"},
		{"rr4---sn-aj5go5-5i.c.youtube.com", "aj5go5"},
		{"R2---SN-GVNUXAXJVH-JX3S.googlevideo.com.", "gvnuxaxjvh"},
		{"rr12---sn-4g5e6nsz.googlevideo.com", "4g5e6nsz"},
		{"redirector.googlevideo.com", ""},
		{"www.youtube.com", ""},
		{"rr4---sn-aj5go5-5i.example.com", ""},
		{"x4---sn-aj5go5.googlevideo.com", ""},
		{"rr---sn-aj5go5.googlevideo.com", ""},
		{"rr4---sn-.googlevideo.com", ""},
		{"rr4---sn-a.b.googlevideo.com", ""},
	} {
		cl, ok := VideoServer(c.host)
		if cl != c.cluster || ok != (c.cluster != "") {
			t.Errorf("%s: %q %v", c.host, cl, ok)
		}
	}
	got := VideoChecks([]string{"www.youtube.com", "rr4---sn-aj5go5-5i.c.youtube.com", "rr1---sn-aj5go5-5p.googlevideo.com",
		"R2---sn-gvnuxaxjvh-jx3s.googlevideo.com", "rr9---sn-other.googlevideo.com"})
	if !slices.Equal(got, []string{"https://rr4---sn-aj5go5-5i.c.youtube.com/generate_204", "https://r2---sn-gvnuxaxjvh-jx3s.googlevideo.com/generate_204"}) {
		t.Fatalf("%q", got)
	}
	if VideoChecks(nil) != nil {
		t.Fatal("none seen: none")
	}
}

func TestParseSwitch(t *testing.T) {
	sw, ok := ParseSwitch("HYROUTE\tswitch\t1794300060\tyoutube\tvideo:aj5go5\t3\t2")
	if !ok || sw != (Switch{At: time.Unix(1794300060, 0), Target: YouTube, Key: "video:aj5go5", Strategy: 3, From: 2}) {
		t.Fatalf("%+v %v", sw, ok)
	}
	for _, l := range []string{"winws2 started", "HYROUTE\tswitch\tx\tyoutube\tk\t1\t0", "HYROUTE\tswitch\t1\tyoutube\t\t1\t0",
		"HYROUTE\tswitch\t1\tyoutube\tk\t0\t1", "HYROUTE\tswitch\t1\tyoutube\tk\t1"} {
		if _, ok := ParseSwitch(l); ok {
			t.Fatalf("%q", l)
		}
	}
}

// The Runner keeps the orchestrator's lines apart from winws2's own, and
// forgets them when it starts winws2 again.
func TestRunnerSwitches(t *testing.T) {
	outs := make(chan io.Writer, 2)
	r := &Runner{Exe: "winws2.exe", Spawn: func(_ string, _, _ []string, out io.Writer) (hysteria.Child, error) {
		outs <- out
		return &fakeChild{done: make(chan struct{})}, nil
	}}
	r.Start([]string{"a"})
	out := <-outs
	io.WriteString(out, "some line\nHYROUTE\tswitch\t1794300000\tyoutube\tyoutube.com\t1\t0\n")
	deadline := time.Now().Add(5 * time.Second)
	for len(r.Switches()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sw := r.Switches(); len(sw) != 1 || sw[0].Key != "youtube.com" || slices.ContainsFunc(r.Status().Lines, func(l string) bool { return strings.HasPrefix(l, "HYROUTE") }) {
		t.Fatalf("%+v %v", sw, r.Status().Lines)
	}
	r.Start([]string{"b"})
	<-outs
	if len(r.Switches()) != 0 {
		t.Fatal("kept over a restart")
	}
	r.Stop()
}
