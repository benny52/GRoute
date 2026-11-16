//go:build integration && windows

package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lardan099/hyroute/internal/awgcore"
	"github.com/lardan099/hyroute/internal/release"
	"golang.org/x/sys/windows"
)

// Exercise the real helper's version/IPC probe and the path chosen for the
// next session across an install, client restart and rollback. All releases
// and state live on the test host.
func TestAWGReleaseFromSettings(t *testing.T) {
	build := func(dir, version string) string {
		t.Helper()
		path := filepath.Join(dir, "groute-awg.exe")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go.exe"), "build", "-trimpath", "-buildvcs=false",
			"-ldflags", "-X main.helperVersion="+version, "-o", path, "./cmd/groute-awg")
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
		return path
	}
	var bundled string
	if dir := os.Getenv("GROUTE_TEST_AWG_DIR"); dir != "" {
		bundled = filepath.Join(dir, "groute-awg.exe")
	} else {
		bundled = build(t.TempDir(), "v1.0.0")
	}
	candidate := build(t.TempDir(), "v99.0.1")
	data, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/repos/benny52/GRoute/releases", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]release.Release{{Tag: "awg-v99.0.1", Assets: []release.Asset{{
			Name: "groute-awg.exe", URL: srv.URL + "/core", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(data)),
		}}}})
	})
	mux.HandleFunc("/core", func(w http.ResponseWriter, r *http.Request) { w.Write(data) })
	dir := filepath.Join(t.TempDir(), "awg")
	reopen := func() *Manager {
		return &Manager{Dir: dir, Kind: AWG, Bundled: bundled, Version: awgcore.HelperVersion, Client: &release.Client{API: srv.URL}}
	}
	m := reopen()
	u, newer, err := m.Check(t.Context())
	if err != nil || !newer || u.Version != "v99.0.1" {
		t.Fatalf("offer: %q, %v, %v", u.Version, newer, err)
	}
	// The production installer protects the parent directory for administrators.
	// Ordinary test runs exercise activation in a fresh user-owned directory.
	install := m.Install
	if !windows.GetCurrentProcessToken().IsElevated() {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		install = m.installPrepared
	}
	if err := install(t.Context(), u, nil); err != nil {
		t.Fatal(err)
	}
	m = reopen()
	if v, err := awgcore.HelperVersion(m.Path()); err != nil || v != "v99.0.1" {
		t.Fatalf("installed helper after restart: %q, %v", v, err)
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := reopen().Path(); got != bundled {
		t.Fatalf("rollback selected %s", got)
	}
}
