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
		"zapret-auto.lua", "--blob=google_tls:@", "--filter-l7=discord,stun",
		// circular before the payload filter, seeing every packet; the
		// methods only the ClientHello.
		"--in-range=-s5556 --lua-desync=circular:fails=3:retrans=2:nld=2 --in-range=x --payload=tls_client_hello --lua-desync=",
		"hostfakesplit:host=discord.com:strategy=8", "--lua-desync=fake:blob=google_tls:tcp_ts=-1000:repeats=7 ",
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
	if sl := strings.Join(sargs, " "); err != nil || strings.Contains(sl, "nld") || !strings.Contains(sl, "circular:fails=3:retrans=2 --in-range=x") {
		t.Fatalf("%v %s", err, sl)
	}
	cl := CommandLine(args)
	if strings.Contains(cl, "data") || !strings.Contains(cl, "--blob=google_tls:@tls_clienthello_www_google_com.bin") {
		t.Fatalf("%s", cl)
	}
}

func TestWriteLists(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLists(dir, nil, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
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
	if !strings.Contains(string(b), "\ndiscord.media\n") {
		t.Fatalf("%q", b)
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
