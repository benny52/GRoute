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
