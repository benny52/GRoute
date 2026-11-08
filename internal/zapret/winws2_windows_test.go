package zapret_test

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	dir := filepath.Join(staged, runtimefiles.ZapretDir)
	lists := t.TempDir()
	if err := zapret.WriteLists(lists, []string{"example.org"}, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}); err != nil {
		t.Fatal(err)
	}
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
		slot   int // a tester's: a probe from its ports goes through it
	}
	cases := map[string]run{}
	var ids []string
	for i, m := range zapret.Methods {
		ids = append(ids, m.ID)
		cases[m.ID] = run{all(zapret.Plan{Methods: []string{m.ID}}), zapret.ProbeOnly(i + 1), i + 1}
	}
	cases["circular"] = run{all(zapret.Plan{Methods: ids, Circular: true}), zapret.ProbeExclude(), 0}
	cases["youtube only"] = run{map[zapret.Target]zapret.Plan{zapret.YouTube: {Methods: ids, Circular: true}}, zapret.ProbeExclude(), 0}
	var mu sync.Mutex
	opened := 0
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: lists, Plans: c.plans, Filter: c.filter})
			if err != nil {
				t.Fatal(err)
			}
			if c.slot > 0 {
				args = append([]string{"--debug=1"}, args...) // shows the packets it took
			}
			var out syncBuffer
			cmd := exec.Command(filepath.Join(dir, "winws2.exe"), args...)
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
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
				r := (&zapret.Prober{Slot: c.slot}).Check(context.Background(), []string{"https://example.com/"})
				t.Logf("example.com through %s: ok %v %v", name, r.OK, r.Failed)
				// Only the probes' ports reach a tester: it took the probe.
				if !strings.Contains(out.String(), "dpi desync src=") {
					t.Errorf("the tester saw no packet of the probe from its ports")
				}
				if r.OK {
					mu.Lock()
					opened++
					mu.Unlock()
				}
			}
			cmd.Process.Kill()
			<-exited
			t.Logf("%s", out.String())
		})
	}
	if opened == 0 {
		t.Fatal("example.com opened through no method: the checks or the testers are broken")
	}
	t.Logf("example.com opened through %d of %d methods", opened, len(zapret.Methods))
}

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
