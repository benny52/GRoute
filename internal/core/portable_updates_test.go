package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/release"
)

func TestPortableCoreReleaseLifecycle(t *testing.T) {
	for _, kind := range []Kind{Hysteria, Xray, AWG} {
		t.Run(kind.Name, func(t *testing.T) {
			const current = "v2.0.0"
			const next = "v2.1.0"
			tag := next
			switch kind.Name {
			case "AmneziaWG":
				tag = "awg-" + next
			case "Hysteria":
				tag = "app/" + next
			}
			asset := []byte(next)
			if kind.Member != "" {
				var buf bytes.Buffer
				z := zip.NewWriter(&buf)
				member, err := z.Create(kind.Member)
				if err != nil {
					t.Fatal(err)
				}
				fmt.Fprint(member, next)
				if err := z.Close(); err != nil {
					t.Fatal(err)
				}
				asset = buf.Bytes()
			}
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256(asset))
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/asset" {
					w.Write(asset)
					return
				}
				if r.URL.Path != "/repos/"+kind.Repo+"/releases" {
					http.NotFound(w, r)
					return
				}
				if kind.Exe == AWG.Exe && r.URL.Query().Get("page") == "" {
					w.Header().Set("Link", `</next>; rel="next"`)
					json.NewEncoder(w).Encode([]release.Release{{Tag: "v999.0.0"}, {Tag: "awg-v99.0.0", Prerelease: true}})
					return
				}
				json.NewEncoder(w).Encode([]release.Release{{Tag: tag, Assets: []release.Asset{{
					Name: kind.Asset, URL: server.URL + "/asset", Digest: digest,
				}}}})
			}))
			defer server.Close()
			dir := t.TempDir()
			cache := filepath.Join(dir, "cores")
			if err := os.Mkdir(cache, 0700); err != nil {
				t.Fatal(err)
			}
			load := func() *Manager {
				return &Manager{Kind: kind, Dir: cache, Bundled: filepath.Join(dir, kind.Exe), Version: fakeVersion, Client: &release.Client{API: server.URL}}
			}
			m := load()
			if err := os.WriteFile(m.Bundled, []byte(current), 0700); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			update, ok, err := m.Check(ctx)
			if err != nil || !ok || update.Tag != tag || update.Version != next {
				t.Fatalf("check: %+v, available=%v, err=%v", update, ok, err)
			}
			// The integration starts at the already prepared, isolated directory.
			// Production uses ProtectDir before entering the same installation path.
			if err := m.installPrepared(ctx, update, nil); err != nil {
				t.Fatal(err)
			}
			m = load()
			if info := m.Info(); info.Version != next || !info.Updated || info.Previous == "" {
				t.Fatalf("reopen: %+v", info)
			}
			if err := m.Rollback(); err != nil || m.Info().Version != current {
				t.Fatalf("rollback: %+v, %v", m.Info(), err)
			}
			bad := update
			bad.sha256 = []string{"incorrect"}
			if err := m.installPrepared(ctx, bad, nil); err == nil {
				t.Fatal("accepted an invalid digest")
			}
			if got, err := os.ReadFile(filepath.Join(cache, next, kind.Exe)); err != nil || string(got) != next {
				t.Fatalf("failed retry damaged saved version: %q, %v", got, err)
			}
			if err := m.installPrepared(ctx, update, nil); err != nil || m.Info().Version != next {
				t.Fatalf("reinstall: %+v, %v", m.Info(), err)
			}
		})
	}
}
