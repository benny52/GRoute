package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAWGExecutableIndependentUpdate(t *testing.T) {
	src, cache := t.TempDir(), t.TempDir()
	var approved string
	digest := func(data string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(data))) }
	get := awgExecutable(src, cache, digest("bundled"), func() string { return approved }, func(dir string) error { return os.MkdirAll(dir, 0700) })
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(src, "groute-awg.exe"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("bundled")
	first, err := get()
	if err != nil {
		t.Fatal(err)
	}
	write("updated")
	if _, err := get(); err == nil {
		t.Fatal("accepted an unapproved replacement")
	}
	approved = digest("updated")
	next, err := get()
	if err != nil || next == first {
		t.Fatalf("independent update: %s, %v", next, err)
	}
	for path, want := range map[string]string{first: "bundled", next: "updated"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("staged %s: %q, %v", path, got, err)
		}
	}
}
