//go:build windows

package update

import (
	"os"
	"path/filepath"
	"testing"
)

// Pinned, neither the file nor a folder above it can be renamed (the way
// to put another program at its path), and the file cannot be rewritten;
// the folder still takes new files. Released, all of it works again.
func TestPinFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Downloads", "HyRoute")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, MainExe)
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := PinFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(exe, exe+".old"); err == nil {
		t.Error("the pinned file was renamed")
	}
	if err := os.WriteFile(exe, []byte("evil"), 0o755); err == nil {
		t.Error("the pinned file was rewritten")
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if err := os.Rename(d, d+"2"); err == nil {
			t.Errorf("%s renamed while pinned", d)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o644); err != nil {
		t.Errorf("a new file in the pinned folder: %v", err)
	}
	if b, err := os.ReadFile(exe); err != nil || string(b) != "MZ" {
		t.Errorf("reading the pinned file: %q %v", b, err)
	}
	release()
	if err := os.Rename(dir, dir+"2"); err != nil {
		t.Errorf("released, the folder stays pinned: %v", err)
	}
}
