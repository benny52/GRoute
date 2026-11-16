package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/store"
)

func TestInstallGRouteBundle(t *testing.T) {
	src, target := t.TempDir(), filepath.Join(t.TempDir(), "GRoute")
	self := filepath.Join(src, "GRoute.exe")
	if err := os.WriteFile(self, []byte("test program"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(src, "browser"), 0700); err != nil {
		t.Fatal(err)
	}
	member := "browser/host.exe"
	path := filepath.Join(src, member)
	if err := os.WriteFile(path, []byte("verified host"), 0600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{member: fmt.Sprintf("%x", sha256.Sum256([]byte("verified host")))}
	for range 2 {
		if err := installGRouteBundle(self, target, files); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installGRouteBundle(self, target, files); err == nil {
		t.Fatal("accepted a changed helper")
	}
	got, err := os.ReadFile(filepath.Join(target, member))
	if err != nil || string(got) != "verified host" {
		t.Fatalf("installed host changed: %q %v", got, err)
	}
}

func TestInstallMigratesPortableProfile(t *testing.T) {
	src, err := store.Open(filepath.Join(t.TempDir(), "Data"))
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "GRoute", "Data")
	save := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	save(src.SaveProfiles(&store.Profiles{Active: "server1", List: []hysteria.Profile{{ID: "server1", Source: "sub:test", Name: "Demo", Host: "demo.example.invalid", Ports: "443", Auth: "test-only"}, {ID: "server2", Name: "Backup", Host: "backup.example.invalid", Ports: "443", Auth: "test-only"}}}))
	save(src.SaveSubscriptions([]store.Subscription{{ID: "test", Name: "Test", URL: "https://example.invalid/sub", Enabled: true}}))
	save(src.PushSnapshot("test", []byte("previous"), nil))
	save(src.PushSnapshot("test", []byte("current"), nil))
	settings := []byte(`{"defaultAction":"tunnel","rules":[{"name":"test","domains":["demo.invalid"],"action":"tunnel","profile":"server1","fallback":["server2"]}]}`)
	save(src.WriteRaw("settings.json", store.RawFile{Exists: true, Data: settings}))
	rulesets := []byte(`{"version":1,"active":"aaaaaaaa0001","list":[{"id":"aaaaaaaa0001","name":"Работа","config":{"defaultAction":"direct"}},{"id":"bbbbbbbb0002","name":"Дом","config":{"defaultAction":"tunnel","defaultProfile":"server2"}}]}`)
	save(src.WriteRaw("rulesets.json", store.RawFile{Exists: true, Data: rulesets}))
	if err := migrateGRouteProfile(dest, func(*os.Root) error { return errors.New("simulated interruption") }); err == nil {
		t.Fatal("partial migration reported success")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("partial profile published", err)
	}
	save(migrateGRouteProfile(dest, src.CopyInstallSettings))
	dst, err := store.Open(dest)
	save(err)
	profiles, err := dst.LoadProfiles()
	save(err)
	if len(profiles.List) != 2 || profiles.Active != "server1" || profiles.List[0].Auth != "test-only" || profiles.List[0].Source != "sub:test" {
		t.Fatal("lost profile link or credential")
	}
	subs, err := dst.LoadSubscriptions()
	save(err)
	if len(subs) != 1 || subs[0].URL != "https://example.invalid/sub" {
		t.Fatal("lost subscription")
	}
	now, err := dst.CurrentSnapshot("test")
	save(err)
	prev, err := dst.PreviousSnapshot("test")
	save(err)
	if string(now) != "current" || string(prev) != "previous" {
		t.Fatal("lost subscription history")
	}
	rs, err := dst.LoadRulesets()
	save(err)
	cfg, _, err := dst.LoadSettings()
	save(err)
	if len(rs.List) != 2 || rs.Active != "aaaaaaaa0001" || cfg.Config.Rules[0].Profile != "server1" || cfg.Config.Rules[0].Fallback[0] != "server2" {
		t.Fatal("lost rule profile or backup")
	}
	save(migrateGRouteProfile(dest, func(*os.Root) error { t.Fatal("existing settings overwritten"); return nil }))
}
