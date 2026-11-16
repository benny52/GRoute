package browser

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/ctl"
)

func TestGRouteBrowserBundle(t *testing.T) {
	if ctl.BrowserHost != "com.groute.browser" || slices.Contains(ctl.BrowserOrigins, "chrome-extension://eocfmelapohehdegpedblilfdfgledai/") {
		t.Fatal("extension or native host still uses HyRoute's identity")
	}
	raw, err := os.ReadFile("com.groute.browser.json")
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(HostManifest("groute-browser-host.exe"), &want); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if !bytes.Equal(a, b) {
		t.Fatal("packaged native messaging manifest differs from host identity")
	}
	popup, err := files.ReadFile("extension/popup.js")
	if err != nil || !bytes.Contains(popup, []byte("'"+ctl.BrowserHost+"'")) {
		t.Fatal("popup does not use the packaged native host")
	}
}

func TestWindowsExtensionSurvivesMove(t *testing.T) {
	shipped := filepath.Join(t.TempDir(), WindowsHost)
	root := filepath.Join(t.TempDir(), "LocalAppData", "GRoute", "Browser")
	if err := os.WriteFile(shipped, []byte("first host"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallWindows(root, shipped); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(shipped); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, WindowsManifest))
	if err != nil || !bytes.Equal(manifest, HostManifest(WindowsHost)) {
		t.Fatalf("installed manifest: %v", err)
	}
	if DiskVersion(filepath.Join(root, "extension")) != Version() {
		t.Fatal("browser lost the unpacked directory")
	}
	host := filepath.Join(root, WindowsHost)
	if b, err := os.ReadFile(host); err != nil || string(b) != "first host" {
		t.Fatalf("installed host: %v", err)
	}
	newHost := filepath.Join(t.TempDir(), WindowsHost)
	if err := os.WriteFile(newHost, []byte("updated host"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallWindows(root, newHost); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(host); err != nil || string(b) != "updated host" {
		t.Fatalf("reinstall from new location: %v", err)
	}
}

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), DirName)
	// An older version's leftovers go; the files are written anew.
	os.MkdirAll(filepath.Join(dir, "old"), 0o755)
	os.WriteFile(filepath.Join(dir, "old", "x.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "stale.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "popup.js"), []byte("old"), 0o644)
	if err := Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"manifest.json", "background.js", "popup.html", "popup.js", "popup.css", "icons/icon128.png"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	for _, f := range []string{"old", "stale.js"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s kept", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "popup.js")); string(b) == "old" {
		t.Fatal("not rewritten")
	}
	if v := DiskVersion(dir); v == "" || v != Version() {
		t.Fatalf("%q %q", v, Version())
	}
	if DiskVersion(t.TempDir()) != "" {
		t.Fatal("version of nothing")
	}
}

// The extension's ID comes from its key: the host lets in that ID only.
func TestManifests(t *testing.T) {
	b, err := files.ReadFile("extension/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Key         string   `json:"key"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Key == "" {
		t.Fatalf("%v %+v", err, m)
	}
	if got := "chrome-extension://" + ExtensionID(m.Key) + "/"; len(ctl.BrowserOrigins) != 1 || ctl.BrowserOrigins[0] != got {
		t.Fatalf("%s, origins %v", got, ctl.BrowserOrigins)
	}
	p := filepath.Join(t.TempDir(), HostFile)
	if err := WriteHostManifest(p, `C:\HyRoute\hyroutectl.exe`); err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	raw, _ := os.ReadFile(p)
	if err := json.Unmarshal(raw, &h); err != nil || h["name"] != ctl.BrowserHost || h["path"] != `C:\HyRoute\hyroutectl.exe` || h["type"] != "stdio" {
		t.Fatalf("%v %v", err, h)
	}
	if err := Remove(filepath.Join(t.TempDir(), "none"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("manifest kept")
	}
}
