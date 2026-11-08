package runtimefiles

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromRepoDeps(t *testing.T) {
	b, err := os.ReadFile("../../build/deps.json")
	if err != nil {
		t.Fatal(err)
	}
	files, err := FromDeps(b)
	if err != nil {
		t.Fatal(err)
	}
	names := ""
	for _, f := range files {
		names += f.Name + " "
		if len(f.SHA256) != 64 || !strings.HasPrefix(f.URL, "https://github.com/") {
			t.Fatalf("%+v", f)
		}
		if f.Member != "" && len(f.ArchiveSHA256) != 64 {
			t.Fatalf("%+v", f)
		}
	}
	if names != "WinDivert.dll WinDivert64.sys hysteria.exe xray.exe " {
		t.Fatalf("%q", names)
	}
}

func TestStage(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(src, "a.exe"), []byte("good"), 0o644)
	files := []File{{Name: "a.exe", SHA256: sum([]byte("good"))}}
	if _, err := Stage(src, dst, files, nil); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dst, files); err != nil {
		t.Fatal(err)
	}
	// The program folder copy is replaced: the verified copy stays and is
	// used; staging does not pick up the new file.
	os.WriteFile(filepath.Join(src, "a.exe"), []byte("evil"), 0o644)
	if _, err := Stage(src, dst, files, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.exe")); string(b) != "good" {
		t.Fatal("staged copy changed")
	}
	// Without a good copy, a replaced file is refused.
	os.Remove(filepath.Join(dst, "a.exe"))
	var me *MismatchError
	if _, err := Stage(src, dst, files, nil); !errors.As(err, &me) {
		t.Fatalf("replaced file accepted: %v", err)
	}
	// A tampered staged copy fails verification.
	os.WriteFile(filepath.Join(dst, "a.exe"), []byte("evil"), 0o644)
	if err := Verify(dst, files); !errors.As(err, &me) {
		t.Fatal("tampered copy passed")
	}
	os.Remove(filepath.Join(src, "a.exe"))
	os.Remove(filepath.Join(dst, "a.exe"))
	if _, err := Stage(src, dst, files, nil); err == nil {
		t.Fatal("missing file accepted")
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestStageDownloads(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	zb := zipOf(t, map[string]string{"pkg/x64/b.dll": "bee", "pkg/x64/c.sys": "sea", "pkg/readme": "r"})
	served := map[string][]byte{"https://h/a.exe": []byte("good"), "https://h/pkg.zip": zb}
	hits := map[string]int{}
	get := func(url string, max int64) ([]byte, error) {
		hits[url]++
		if b, ok := served[url]; ok {
			return b, nil
		}
		return nil, errors.New("404")
	}
	files := []File{
		{Name: "a.exe", SHA256: sum([]byte("good")), URL: "https://h/a.exe"},
		{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "https://h/pkg.zip", Member: "pkg/x64/b.dll", ArchiveSHA256: sum(zb)},
		{Name: "c.sys", SHA256: sum([]byte("sea")), URL: "https://h/pkg.zip", Member: "pkg/x64/c.sys", ArchiveSHA256: sum(zb)},
	}
	// The program folder has a replaced b.dll and nothing else.
	os.WriteFile(filepath.Join(src, "b.dll"), []byte("evil"), 0o644)
	res, err := Stage(src, dst, files, get)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Downloaded, ",") != "a.exe,c.sys" || strings.Join(res.Replaced, ",") != "b.dll" {
		t.Fatalf("%+v", res)
	}
	if hits["https://h/pkg.zip"] != 1 {
		t.Fatalf("archive fetched %d times", hits["https://h/pkg.zip"])
	}
	if err := Verify(dst, files); err != nil {
		t.Fatal(err)
	}
	// Staged copies are kept: nothing is fetched again.
	res, err = Stage(src, dst, files, get)
	if err != nil || len(res.Downloaded)+len(res.Replaced) != 0 || len(hits) != 2 {
		t.Fatalf("%+v %v %v", res, err, hits)
	}
}

func TestStageDownloadChecked(t *testing.T) {
	zb := zipOf(t, map[string]string{"x/b.dll": "bee"})
	cases := map[string]struct {
		f     File
		serve []byte
	}{
		"file hash":    {File{Name: "a.exe", SHA256: sum([]byte("good")), URL: "u"}, []byte("evil")},
		"archive hash": {File{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "u", Member: "x/b.dll", ArchiveSHA256: sum([]byte("other"))}, zb},
		"member hash":  {File{Name: "b.dll", SHA256: sum([]byte("wasp")), URL: "u", Member: "x/b.dll", ArchiveSHA256: sum(zb)}, zb},
		"no member":    {File{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "u", Member: "y/b.dll", ArchiveSHA256: sum(zb)}, zb},
	}
	for name, c := range cases {
		dst := t.TempDir()
		get := func(string, int64) ([]byte, error) { return c.serve, nil }
		if _, err := Stage(t.TempDir(), dst, []File{c.f}, get); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dst, c.f.Name)); err == nil {
			t.Errorf("%s: file written", name)
		}
	}
}

// zapret2's files: winws2.exe and its DLLs in zapret\, the Lua libraries
// in zapret\lua\, the fakes in zapret\blobs\, all from the release zip.
func TestZapretFromRepoDeps(t *testing.T) {
	b, err := os.ReadFile("../../build/deps.json")
	if err != nil {
		t.Fatal(err)
	}
	files, err := ZapretFromDeps(b)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
		if len(f.SHA256) != 64 || len(f.ArchiveSHA256) != 64 || f.Member == "" || !f.Fetched || !strings.HasPrefix(f.URL, "https://github.com/bol-van/zapret2/") {
			t.Fatalf("%+v", f)
		}
	}
	want := "zapret/WinDivert.dll zapret/WinDivert64.sys zapret/blobs/quic_initial_www_google_com.bin zapret/blobs/tls_clienthello_vk_com.bin zapret/blobs/tls_clienthello_www_google_com.bin " +
		"zapret/cygwin1.dll zapret/lua/zapret-antidpi.lua zapret/lua/zapret-auto.lua zapret/lua/zapret-lib.lua zapret/winws2.exe"
	if strings.Join(names, " ") != want {
		t.Fatalf("%s", strings.Join(names, " "))
	}
	// Staged into subfolders.
	zb := zipOf(t, map[string]string{"z/lua/x.lua": "lua"})
	dst := t.TempDir()
	f := File{Name: "zapret/lua/x.lua", SHA256: sum([]byte("lua")), URL: "https://h/z.zip", Member: "z/lua/x.lua", ArchiveSHA256: sum(zb), Fetched: true}
	// A download that fails says so (not «распакуйте архив HyRoute»).
	if _, err := Stage(t.TempDir(), dst, []File{f}, func(string, int64) ([]byte, error) { return nil, errors.New("offline") }); err == nil ||
		strings.Contains(err.Error(), "распакуйте") || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("%v", err)
	}
	if res, err := Stage(t.TempDir(), dst, []File{f}, func(string, int64) ([]byte, error) { return zb, nil }); err != nil || len(res.Downloaded) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if err := Verify(dst, []File{f}); err != nil {
		t.Fatal(err)
	}
	// Staged once: not downloaded again.
	if res, err := Stage(t.TempDir(), dst, []File{f}, nil); err != nil || len(res.Downloaded) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}
