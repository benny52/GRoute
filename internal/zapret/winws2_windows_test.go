package zapret_test

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	buildfiles "github.com/lardan099/hyroute/build"
	"github.com/lardan099/hyroute/internal/runtimefiles"
	"github.com/lardan099/hyroute/internal/zapret"
)

// TestWinws2Runs downloads the pinned zapret2 release and runs the real
// winws2 with every command line HyRoute builds: each method alone and
// the circular plan, for all services. winws2 checks its options, loads the
// Lua libraries, the blobs and the lists, and opens WinDivert; a line it
// does not accept ends it at once. CI runs it (elevated runner) with
// HYROUTE_ZAPRET_TEST=1.
func TestWinws2Runs(t *testing.T) {
	if os.Getenv("HYROUTE_ZAPRET_TEST") == "" {
		t.Skip("HYROUTE_ZAPRET_TEST=1 runs it: downloads zapret2, needs administrator rights")
	}
	dir, lists := stageZapret(t)
	all := func(p zapret.Plan) map[zapret.Target]zapret.Plan {
		m := map[zapret.Target]zapret.Plan{}
		for _, tg := range zapret.Targets {
			m[tg] = p
		}
		return m
	}
	// As HyRoute runs them: the user's bypass skips the probes' ports, a
	// pick's tester takes only its slot's.
	type run struct {
		plans  map[zapret.Target]zapret.Plan
		filter string
		slot   int    // a tester's: a probe from its ports goes through it
		url    string // what the probe opens ("": example.com)
	}
	cases := map[string]run{}
	var ids []string
	for i, m := range zapret.Methods {
		ids = append(ids, m.ID)
		cases[m.ID] = run{all(zapret.Plan{Methods: []string{m.ID}}), zapret.ProbeOnly(i + 1), i + 1, ""}
	}
	cases["circular"] = run{all(zapret.Plan{Methods: ids, Circular: true}), zapret.ProbeExclude(), 0, ""}
	// The orchestrator on a real connection, starting from a method that
	// opens example.com (fake-md5-seqovl).
	first := append([]string{"fake-md5-seqovl"}, slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == "fake-md5-seqovl" })...)
	cases["circular probed"] = run{all(zapret.Plan{Methods: first, Circular: true}), zapret.ProbeOnly(zapret.ProbeSlots - 1), zapret.ProbeSlots - 1, ""}
	// YouTube's circular on a real video server: HyRoute's host key
	// (hyroute_hostkey) keys it by its cluster. The slot is circular
	// probed's: the cases run one after another.
	cases["youtube video"] = run{map[zapret.Target]zapret.Plan{zapret.YouTube: {Methods: first, Circular: true}}, zapret.ProbeOnly(zapret.ProbeSlots - 1), zapret.ProbeSlots - 1,
		"https://rr4---sn-aj5go5-5i.googlevideo.com/generate_204"}
	cases["youtube only"] = run{map[zapret.Target]zapret.Plan{zapret.YouTube: {Methods: ids, Circular: true}}, zapret.ProbeExclude(), 0, ""}
	var mu sync.Mutex
	opened := 0
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: lists, Plans: c.plans, Filter: c.filter, Sites: testSites})
			if err != nil {
				t.Fatal(err)
			}
			args = append([]string{"--debug=1"}, args...) // shows the packets it took
			cmd, out, exited := startWinws(t, filepath.Join(dir, "winws2.exe"), args)
			select {
			case err := <-exited:
				t.Fatalf("winws2 exited (%v):\n%s\n%s", err, zapret.CommandLine(args), out.String())
			case <-time.After(4 * time.Second):
			}
			if c.slot > 0 {
				// example.com (in the own-sites list) through this method,
				// from the tester's ports: the whole chain works. A method
				// may break an unblocked site; all of them would mean a
				// broken chain (checked below).
				url := c.url
				if url == "" {
					url = "https://example.com/"
				}
				r := (&zapret.Prober{Slot: c.slot}).Check(context.Background(), []string{url})
				t.Logf("%s through %s: ok %v %v", url, name, r.OK, r.Failed)
				// Only the probes' ports reach a tester: it took the probe.
				if !strings.Contains(out.String(), "dpi desync src=") {
					t.Errorf("the tester saw no packet of the probe from its ports")
				}
				if r.OK && c.url == "" {
					mu.Lock()
					opened++
					mu.Unlock()
				}
			}
			if c.slot == 0 {
				// The user's bypass: a probe's packets never reach it.
				(&zapret.Prober{Slot: 1}).Check(context.Background(), []string{"https://example.com/"})
				if m := probePort.FindString(out.String()); m != "" {
					t.Errorf("the user's winws2 took a probe's packet: %s", m)
				}
			}
			cmd.Process.Kill()
			<-exited
			if o := out.String(); strings.Contains(o, "LUA ERROR") || strings.Contains(o, "invalid success detector") {
				t.Errorf("Lua failed:\n%s", o)
			}
			if name == "circular probed" && !strings.Contains(out.String(), "circular: current strategy") {
				t.Errorf("the orchestrator saw nothing")
			}
			if name == "youtube video" && !strings.Contains(out.String(), ".video:aj5go5'") {
				t.Errorf("the video server was not keyed by its cluster")
			}
			t.Logf("%s", out.String())
		})
	}
	// A method's fakes must die before the server: one that reaches it
	// breaks an unblocked site's handshake (tcp_ts alone did on Windows).
	t.Logf("example.com opened through %d of %d methods", opened, len(zapret.Methods))
	if opened < len(zapret.Methods)-1 {
		t.Fatalf("example.com opened through %d of %d methods: the fakes of the others reach the server", opened, len(zapret.Methods))
	}
}

// stageZapret downloads and stages the pinned zapret2 (once per test) and
// writes the lists: example.com is an own site, so a probe to it goes
// through the methods (their Lua runs on it).
func stageZapret(t *testing.T) (dir, lists string) {
	t.Helper()
	files, err := runtimefiles.ZapretFromDeps(buildfiles.Deps)
	if err != nil {
		t.Fatal(err)
	}
	// Not t.TempDir: the WinDivert driver loaded from this folder keeps
	// WinDivert64.sys locked until Windows unloads it, so the folder is
	// removed best-effort.
	staged, err := os.MkdirTemp("", "hyroute-zapret-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(staged) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := runtimefiles.Stage(t.TempDir(), staged, files, runtimefiles.HTTPGetter(ctx, http.DefaultClient, "HyRoute-test")); err != nil {
		t.Fatal(err)
	}
	lists = t.TempDir()
	if err := zapret.WriteLists(lists, testSites, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(staged, runtimefiles.ZapretDir), lists
}

// testSites are the own sites of the tests: names, and documentation
// networks that give the profiles by address (--ipset) to winws2.
var testSites = []string{"example.com", "example.org", "203.0.113.0/24", "2001:db8:1::/48"}

// TestWinws2Generated runs generated strategies (a spread over the whole
// space, the neighbors of a library method and Known) in the real winws2, twelve
// at once as a pick does, each with a probe to example.com from its
// ports: no Lua function may fail on a real connection.
func TestWinws2Generated(t *testing.T) {
	if os.Getenv("HYROUTE_ZAPRET_TEST") == "" {
		t.Skip("HYROUTE_ZAPRET_TEST=1 runs it: downloads zapret2, needs administrator rights")
	}
	dir, lists := stageZapret(t)
	var ids []string
	for _, s := range zapret.Broad(18, 42) {
		ids = append(ids, s.ID())
	}
	base, _ := zapret.AsStrategy("fake-vk-seqovl")
	for _, s := range zapret.Neighbors(base)[:6] {
		ids = append(ids, s.ID())
	}
	for _, s := range zapret.Known() { // Flowseal's recipes, HyRoute's own fooling among them
		ids = append(ids, s.ID())
	}
	opened, total := 0, len(ids)
	for len(ids) > 0 {
		batch := ids[:min(len(ids), zapret.ProbeSlots-1)]
		ids = ids[len(batch):]
		type run struct {
			cmd    *exec.Cmd
			out    *syncBuffer
			exited chan error
		}
		runs := make([]run, len(batch))
		for i, id := range batch {
			args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: lists, Filter: zapret.ProbeOnly(i + 1),
				Plans: map[zapret.Target]zapret.Plan{zapret.Sites: {Methods: []string{id}}}})
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			var r run
			r.cmd, r.out, r.exited = startWinws(t, filepath.Join(dir, "winws2.exe"), append([]string{"--debug=1"}, args...))
			runs[i] = r
		}
		time.Sleep(3 * time.Second)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i, id := range batch {
			select {
			case err := <-runs[i].exited:
				t.Errorf("%s: winws2 exited (%v):\n%s", id, err, runs[i].out.String())
				continue
			default:
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := (&zapret.Prober{Slot: i + 1}).Check(context.Background(), []string{"https://example.com/"})
				mu.Lock()
				defer mu.Unlock()
				if r.OK {
					opened++
				}
				t.Logf("%s: ok %v %v", id, r.OK, r.Failed)
			}()
		}
		wg.Wait()
		for i, id := range batch {
			runs[i].cmd.Process.Kill()
			<-runs[i].exited
			out := runs[i].out.String()
			if strings.Contains(out, "LUA ERROR") || strings.Contains(out, "desync ERROR") {
				t.Errorf("%s failed in winws2:\n%s", id, out)
			}
			if !strings.Contains(out, "hostlist check for example.com : positive") && !strings.Contains(out, "example.com : positive") {
				t.Logf("%s: the probe did not reach its profile", id)
			}
		}
	}
	t.Logf("example.com opened through %d of %d generated strategies", opened, total)
	if opened*4 < total*3 {
		t.Fatalf("example.com opened through %d of %d generated strategies: their fakes reach the server", opened, total)
	}

}

// startWinws starts winws2 as the Runner does: again, at once, when it
// did not initialize (0xC0000142, cygwin1.dll as another winws2 dies).
func startWinws(t *testing.T, exe string, args []string) (*exec.Cmd, *syncBuffer, chan error) {
	t.Helper()
	for try := 0; ; try++ {
		out := &syncBuffer{}
		cmd := exec.Command(exe, args...)
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		select {
		case err := <-exited:
			if zapret.DLLInitFailed(err) && try < 3 {
				t.Logf("winws2 did not initialize (%v): again", err)
				time.Sleep(300 * time.Millisecond)
				continue
			}
			again := make(chan error, 1)
			again <- err
			return cmd, out, again
		case <-time.After(time.Second):
			return cmd, out, exited
		}
	}
}

// probePort matches a packet from or to a probe's port in winws2's log.
var probePort = regexp.MustCompile(`[sd]port=(30\d\d\d|31[0-8]\d\d|319[0-4]\d)\b`)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
