package update

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func appZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	for name, body := range entries {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
	return p
}

const plist = `<plist><dict><key>CFBundleShortVersionString</key>
	<string>1.3.13</string></dict></plist>`

func TestExtractAndVerifyApp(t *testing.T) {
	ok := map[string]string{"HyRoute.app/Contents/Info.plist": plist, "__MACOSX/._x": "meta"}
	for _, f := range AppFiles {
		ok["HyRoute.app/"+f] = "bin"
	}
	dst := filepath.Join(t.TempDir(), "files")
	if err := extractApp(appZip(t, ok), dst); err != nil {
		t.Fatal(err)
	}
	m, err := VerifyApp(dst)
	if err != nil || m.Version != "v1.3.13" {
		t.Fatalf("%+v %v", m, err)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "HyRoute.app/Contents/MacOS/HyRoute")); fi.Mode()&0o111 == 0 {
		t.Fatal("not executable")
	}
	for _, bad := range []string{"../evil", "HyRoute.app/../../evil", "/abs", "Other.app/x", `HyRoute.app\x`} {
		if err := extractApp(appZip(t, map[string]string{bad: "x"}), filepath.Join(t.TempDir(), "f")); err == nil {
			t.Fatalf("%q extracted", bad)
		}
	}
	delete(ok, "HyRoute.app/Contents/Resources/xray")
	dst2 := filepath.Join(t.TempDir(), "files")
	extractApp(appZip(t, ok), dst2)
	if _, err := VerifyApp(dst2); err == nil {
		t.Fatal("a bundle without xray verified")
	}
}
