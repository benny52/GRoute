package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/release"
)

// xrayZip is a release zip holding exe (the fake core: its version as
// text) and the files beside it in the real one.
func xrayZip(t *testing.T, exe string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range map[string]string{"xray.exe": exe, "geoip.dat": "geo", "../evil.exe": "no"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return b.Bytes()
}

func TestXrayCheckInstall(t *testing.T) {
	zipBody := xrayZip(t, "v26.11.20")
	sum := sha256.Sum256(zipBody)
	hexSum := hex.EncodeToString(sum[:])
	dgst := "MD5= 00\nSHA1= 00\nSHA2-256= " + strings.ToUpper(hexSum) + "\nSHA2-512= 00\n"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/XTLS/Xray-core/releases":
			json.NewEncoder(w).Encode([]release.Release{
				{Tag: "v26.12.1", Prerelease: true},
				{Tag: "v26.11.20", Body: "notes", Assets: []release.Asset{
					{Name: "Xray-windows-64.zip", URL: srv.URL + "/zip"},
					{Name: "Xray-windows-64.zip.dgst", URL: srv.URL + "/dgst"},
				}},
			})
		case "/zip":
			w.Write(zipBody)
		case "/dgst":
			w.Write([]byte(dgst))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "xray.exe")
	os.WriteFile(bundled, []byte("v26.10.31"), 0o755)
	tested := ""
	m := &Manager{Kind: Xray, Dir: filepath.Join(dir, "xray"), Bundled: bundled, Client: &release.Client{API: srv.URL}, Version: fakeVersion,
		Test: func(p string) error { tested = p; return nil }}

	u, ok, err := m.Check(context.Background())
	if err != nil || !ok || u.Version != "v26.11.20" || len(u.sha256) != 1 || u.sha256[0] != hexSum {
		t.Fatalf("%+v %v %v", u, ok, err)
	}
	if err := m.Install(context.Background(), u, nil); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(m.Dir, "v26.11.20", "xray.exe")
	if m.Path() != want || tested != want || m.Info().Version != "v26.11.20" {
		t.Fatalf("%s %s %+v", m.Path(), tested, m.Info())
	}
	// Only xray.exe came out of the archive; the zip itself is gone.
	ents, _ := os.ReadDir(filepath.Join(m.Dir, "v26.11.20"))
	if len(ents) != 1 {
		t.Fatalf("%v", ents)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.exe")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an archive name reached the disk")
	}
	if p := m.Paths(); len(p) != 2 || p[0] != want || p[1] != bundled {
		t.Fatalf("%v", p)
	}
	if err := m.Rollback(); err != nil || m.Path() != bundled {
		t.Fatalf("%v %s", err, m.Path())
	}
}

// A new core that does not take the user's configs is not installed.
func TestXrayTestRefuses(t *testing.T) {
	zipBody := xrayZip(t, "v26.11.20")
	sum := sha256.Sum256(zipBody)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(zipBody) }))
	defer srv.Close()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "xray.exe")
	os.WriteFile(bundled, []byte("v26.10.31"), 0o755)
	m := &Manager{Kind: Xray, Dir: filepath.Join(dir, "xray"), Bundled: bundled, Client: &release.Client{API: srv.URL}, Version: fakeVersion,
		Test: func(string) error { return errors.New("«NL»: unknown field") }}
	u := Update{Version: "v26.11.20", url: srv.URL + "/zip", sha256: []string{hex.EncodeToString(sum[:])}}
	err := m.Install(context.Background(), u, nil)
	if err == nil || !strings.Contains(err.Error(), "не принимает настройки ваших серверов") || !strings.Contains(err.Error(), "«NL»") {
		t.Fatalf("%v", err)
	}
	if m.Path() != bundled {
		t.Fatal("the refused core is in use")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "v26.11.20")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the refused core was kept")
	}
	// A zip that is not the one of the sums is not opened at all.
	u.sha256 = []string{strings.Repeat("0", 64)}
	m.Test = nil
	if err := m.Install(context.Background(), u, nil); err == nil {
		t.Fatal("a zip with another checksum installed")
	}
}

func TestXrayNoSums(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]release.Release{{Tag: "v26.11.20", Assets: []release.Asset{{Name: "Xray-windows-64.zip", URL: srv.URL + "/zip"}}}})
	}))
	defer srv.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "xray.exe"), []byte("v26.10.31"), 0o755)
	m := &Manager{Kind: Xray, Dir: filepath.Join(dir, "xray"), Bundled: filepath.Join(dir, "xray.exe"), Client: &release.Client{API: srv.URL}, Version: fakeVersion}
	if _, ok, err := m.Check(context.Background()); ok || err == nil {
		t.Fatalf("offered without checksums: %v", err)
	}
}
