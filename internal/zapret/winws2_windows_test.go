package zapret_test

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	cases := map[string]map[zapret.Target]zapret.Plan{}
	var ids []string
	for _, m := range zapret.Methods {
		ids = append(ids, m.ID)
		cases[m.ID] = all(zapret.Plan{Methods: []string{m.ID}})
	}
	cases["circular"] = all(zapret.Plan{Methods: ids, Circular: true})
	cases["youtube only"] = map[zapret.Target]zapret.Plan{zapret.YouTube: {Methods: ids, Circular: true}}
	for name, plans := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := zapret.Build(zapret.BuildConfig{Dir: dir, Lists: lists, Plans: plans})
			if err != nil {
				t.Fatal(err)
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
			cmd.Process.Kill()
			<-exited
			t.Logf("%s", out.String())
		})
	}
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
