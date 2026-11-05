//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsProgram(t *testing.T) {
	d := t.TempDir()
	mk := func(name string, dir bool, mode os.FileMode) string {
		p := filepath.Join(d, name)
		if dir {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for p, want := range map[string]bool{
		mk("Discord.app", true, 0):    true,
		mk("folder", true, 0):         false,
		mk("tool", false, 0o755):      true,
		mk("notes.txt", false, 0o644): false,
		filepath.Join(d, "missing"):   false,
	} {
		if got := isProgram(p); got != want {
			t.Errorf("%s: %v", filepath.Base(p), got)
		}
	}
}

func TestReplaceBundle(t *testing.T) {
	d := t.TempDir()
	write := func(app, content string) {
		p := filepath.Join(d, app, "Contents", "MacOS", "HyRoute")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("new/HyRoute.app", "new")
	write("Applications/HyRoute.app", "old")
	target := filepath.Join(d, "Applications", "HyRoute.app")
	if err := replaceBundle(filepath.Join(d, "new", "HyRoute.app"), target); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(target, "Contents", "MacOS", "HyRoute"))
	if string(b) != "new" {
		t.Fatalf("%q", b)
	}
	for _, left := range []string{".new", ".old"} {
		if _, err := os.Stat(target + left); err == nil {
			t.Errorf("%s left", left)
		}
	}
	if err := replaceBundle(filepath.Join(d, "new", "HyRoute.app"), filepath.Join(d, "Other.app")); err == nil {
		t.Fatal("replaced an app of another name")
	}
}
