package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserNavigationStartup(t *testing.T) {
	fail := errors.New("launch failed")
	target := "browser://extensions/"
	var tmp string
	launch := func(exe, args string) error {
		const prefix = "--new-window "
		if exe != "chosen.exe" || !strings.HasPrefix(args, prefix) {
			t.Fatalf("unexpected launch: %q, %q", exe, args)
		}
		tmp = strings.Trim(strings.TrimPrefix(args, prefix), `"`)
		page, err := os.ReadFile(tmp)
		if err != nil {
			t.Fatal(err)
		}
		marker := strings.TrimSuffix(filepath.Base(tmp), ".html")
		if !strings.Contains(string(page), "<title>"+marker+"</title>") || !strings.Contains(string(page), target) {
			t.Fatal("temporary page is missing its window marker or destination")
		}
		return fail
	}
	if err := navigateBrowserExtensionsWith("chosen.exe", target, launch); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary page survived launch failure")
	}
	if err := navigateBrowserExtensionsWith("", "https://example.invalid", nil); err == nil {
		t.Fatal("accepted an external destination")
	}
}

func TestExtensionsURLConfirmation(t *testing.T) {
	for _, s := range []string{"browser://extensions/", "chrome://extensions"} {
		if !extensionLocation(s, "browser://extensions/") {
			t.Errorf("valid management page %q", s)
		}
	}
	for _, s := range []string{"", "https://extensions/", "browser://extensions-other/", "https://example.invalid/#browser://extensions/"} {
		if extensionLocation(s, "browser://extensions/") {
			t.Errorf("not a management page: %q", s)
		}
	}
}
