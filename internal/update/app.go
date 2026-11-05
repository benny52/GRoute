package update

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lardan099/hyroute/internal/release"
)

// The macOS package is HyRoute.app zipped (ditto): its integrity is the
// zip's checksum from SHA256SUMS; the bundle is then read from the
// service's own folder.

// PlatformMac is the macOS asset's platform part.
const PlatformMac = "macos-universal"

// AppBundle is the bundle's name in the package.
const AppBundle = "HyRoute.app"

// stageApp downloads the macOS package into root/<version>, extracts
// HyRoute.app into root/<version>/files and checks it.
func stageApp(ctx context.Context, c *release.Client, a Available, root string, progress func(done, total int64)) (string, error) {
	dir := filepath.Join(root, a.Version)
	os.RemoveAll(dir)
	zipPath := filepath.Join(dir, "package.zip")
	if _, err := c.Download(ctx, a.zipURL, zipPath, 300<<20, progress, a.sums...); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	files := filepath.Join(dir, "files")
	if err := extractApp(zipPath, files); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("пакет повреждён: %w", err)
	}
	m, err := VerifyApp(files)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if release.Compare(m.Version, a.Version) != 0 {
		os.RemoveAll(dir)
		return "", fmt.Errorf("пакет версии %s вместо %s", m.Version, a.Version)
	}
	os.Remove(zipPath)
	return files, nil
}

// extractApp takes HyRoute.app out of the zip: only regular files and
// folders under HyRoute.app/, no links, no way out of dst. ditto's
// __MACOSX metadata is skipped.
func extractApp(zipPath, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	var total uint64
	for _, f := range zr.File {
		name := f.Name
		if strings.HasPrefix(name, "__MACOSX/") {
			continue
		}
		clean := path.Clean(name)
		if clean != strings.TrimSuffix(name, "/") || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." ||
			strings.Contains(name, `\`) || !(clean == AppBundle || strings.HasPrefix(clean, AppBundle+"/")) {
			return fmt.Errorf("недопустимое имя в пакете: %q", name)
		}
		target := filepath.Join(dst, filepath.FromSlash(clean))
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("%s: не обычный файл", name)
		}
		total += f.UncompressedSize64
		if f.UncompressedSize64 > 300<<20 || total > 600<<20 {
			return fmt.Errorf("%s: слишком большой", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if mode&0o111 != 0 {
			perm = 0o755
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 300<<20))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

var shortVersion = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`)

// AppFiles are the files the macOS package must have.
var AppFiles = []string{"Contents/MacOS/HyRoute", "Contents/Resources/hysteria", "Contents/Resources/xray", "Contents/Resources/hyroutectl"}

// VerifyApp checks the extracted bundle in dir: its files are there and
// its version is read from its Info.plist.
func VerifyApp(dir string) (Manifest, error) {
	app := filepath.Join(dir, AppBundle)
	b, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if err != nil {
		return Manifest{}, errors.New("в пакете нет " + AppBundle)
	}
	m := shortVersion.FindSubmatch(b)
	if m == nil {
		return Manifest{}, errors.New("в Info.plist нет версии")
	}
	for _, f := range AppFiles {
		fi, err := os.Lstat(filepath.Join(app, filepath.FromSlash(f)))
		if err != nil || !fi.Mode().IsRegular() {
			return Manifest{}, fmt.Errorf("в пакете нет %s", f)
		}
	}
	return Manifest{Version: "v" + strings.TrimPrefix(string(m[1]), "v")}, nil
}
