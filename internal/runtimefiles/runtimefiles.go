// Package runtimefiles moves the binaries HyRoute runs with administrator
// rights (hysteria.exe, xray.exe, WinDivert.dll, WinDivert64.sys) out of the program
// folder before use. The program folder may be writable by the user (a
// portable copy in Downloads); any process of that user could replace a
// file there and have it run elevated. Each file is checked against the
// SHA-256 pinned in deps.json at build time and copied into a directory
// only administrators can write; HyRoute loads and starts the copies.
// A file the program folder lacks (or holds a wrong copy of) is downloaded
// from the URL pinned in deps.json, checked the same way.
package runtimefiles

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// File is one binary and its expected SHA-256 (lower-case hex).
type File struct {
	Name   string
	SHA256 string
	// URL serves the file itself or, with Member set, a zip archive that
	// holds it at path Member; ArchiveSHA256 pins that archive.
	URL, Member, ArchiveSHA256 string
	// Fetched: never in the program folder, only downloaded (zapret2).
	Fetched bool
}

// archive is a zip in deps.json and the files HyRoute takes from it
// (WinDivert, Xray).
type archive struct {
	URL    string            `json:"url"`
	SHA256 string            `json:"sha256"`
	Files  map[string]string `json:"files"`
}

// FromDeps reads the pinned hashes from deps.json.
func FromDeps(b []byte) ([]File, error) {
	var d struct {
		Hysteria struct {
			URL    string `json:"url"`
			Dest   string `json:"dest"`
			SHA256 string `json:"sha256"`
		} `json:"hysteria"`
		WinDivert archive `json:"windivert"`
		Xray      archive `json:"xray"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("deps.json: %w", err)
	}
	if d.Hysteria.Dest == "" || d.Hysteria.SHA256 == "" || len(d.WinDivert.Files) == 0 || len(d.Xray.Files) == 0 {
		return nil, errors.New("deps.json: no pinned files")
	}
	out := []File{{Name: d.Hysteria.Dest, SHA256: strings.ToLower(d.Hysteria.SHA256), URL: d.Hysteria.URL}}
	for _, a := range []archive{d.WinDivert, d.Xray} {
		for p, sum := range a.Files {
			out = append(out, File{Name: path.Base(p), SHA256: strings.ToLower(sum),
				URL: a.URL, Member: p, ArchiveSHA256: strings.ToLower(a.SHA256)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ZapretDir is the folder of zapret2's files among the staged copies.
const ZapretDir = "zapret"

// ZapretFromDeps reads the pinned zapret2 files (winws2.exe with its DLLs,
// the Lua libraries, the fake payloads): staged on demand, when the DPI
// bypass is turned on, into ZapretDir (lua\ and blobs\ under it).
func ZapretFromDeps(b []byte) ([]File, error) {
	var d struct {
		Zapret archive `json:"zapret2"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("deps.json: %w", err)
	}
	if len(d.Zapret.Files) == 0 {
		return nil, errors.New("deps.json: no zapret2 files")
	}
	var out []File
	for p, s := range d.Zapret.Files {
		name := path.Join(ZapretDir, path.Base(p))
		switch {
		case strings.HasSuffix(p, ".lua"):
			name = path.Join(ZapretDir, "lua", path.Base(p))
		case strings.HasSuffix(p, ".bin"):
			name = path.Join(ZapretDir, "blobs", path.Base(p))
		}
		out = append(out, File{Name: name, SHA256: strings.ToLower(s), URL: d.Zapret.URL, Member: p,
			ArchiveSHA256: strings.ToLower(d.Zapret.SHA256), Fetched: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// MismatchError: a file in the program folder is not the one HyRoute was
// built with (damaged, or replaced).
type MismatchError struct {
	Name, Path string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("файл %s не совпадает с тем, с которым собран HyRoute: он повреждён или подменён. "+
		"Скачайте архив HyRoute заново и распакуйте его в новую папку", e.Path)
}

// Getter downloads a URL (at most max bytes).
type Getter func(url string, max int64) ([]byte, error)

// Result lists what Stage had to fetch.
type Result struct {
	// Downloaded: files the program folder lacked, fetched from their URL.
	Downloaded []string
	// Replaced: program-folder files that did not match their hash; a
	// downloaded copy was used instead.
	Replaced []string
}

// maxDownload bounds one download (hysteria.exe is about 25 MB, the Xray
// zip about 17).
const maxDownload = 96 << 20

// Stage makes dst hold verified copies of files from src. dst must already
// be protected (writable by administrators only). A copy that is already
// correct is kept. Each source file is read once into memory, hashed and
// written from that buffer, so it cannot change between check and copy.
// A file missing from src or not matching its hash is downloaded with get
// (nil = no downloads: the file is an error).
func Stage(src, dst string, files []File, get Getter) (Result, error) {
	var res Result
	archives := map[string][]byte{} // URL -> verified zip
	for _, f := range files {
		target := filepath.Join(dst, f.Name)
		if b, err := os.ReadFile(target); err == nil && sum(b) == f.SHA256 {
			continue
		}
		if f.Fetched {
			if get == nil || f.URL == "" {
				return res, fmt.Errorf("нет файла %s", f.Name)
			}
			b, err := download(f, get, archives)
			if err != nil {
				return res, err
			}
			res.Downloaded = append(res.Downloaded, f.Name)
			if err := place(target, b); err != nil {
				return res, err
			}
			continue
		}
		srcPath := filepath.Join(src, f.Name)
		b, err := os.ReadFile(srcPath)
		var bad error
		switch {
		case err != nil:
			bad = fmt.Errorf("нет файла %s: распакуйте архив HyRoute целиком", srcPath)
		case sum(b) != f.SHA256:
			bad = &MismatchError{Name: f.Name, Path: srcPath}
		}
		if bad != nil {
			if get == nil || f.URL == "" {
				return res, bad
			}
			var derr error
			b, derr = download(f, get, archives)
			if derr != nil {
				return res, fmt.Errorf("%w; скачать его не удалось: %v", bad, derr)
			}
			if err == nil {
				res.Replaced = append(res.Replaced, f.Name)
			} else {
				res.Downloaded = append(res.Downloaded, f.Name)
			}
		}
		if err := place(target, b); err != nil {
			return res, err
		}
	}
	return res, nil
}

// place writes b to target through a temporary file.
func place(target string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		// The target may be in use (WinDivert.dll of a running
		// session, a driver being loaded): an identical file is fine.
		if cur, rerr := os.ReadFile(target); rerr == nil && bytes.Equal(cur, b) {
			return nil
		}
		return fmt.Errorf("не удалось обновить %s: %w", target, err)
	}
	return nil
}

// download fetches f (from its archive when it has one) and checks every
// pinned hash.
func download(f File, get Getter, archives map[string][]byte) ([]byte, error) {
	if f.Member == "" {
		b, err := get(f.URL, maxDownload)
		if err != nil {
			return nil, err
		}
		if s := sum(b); s != f.SHA256 {
			return nil, fmt.Errorf("%s: контрольная сумма %s, ожидалась %s", f.URL, s, f.SHA256)
		}
		return b, nil
	}
	zb, ok := archives[f.URL]
	if !ok {
		var err error
		if zb, err = get(f.URL, maxDownload); err != nil {
			return nil, err
		}
		if s := sum(zb); f.ArchiveSHA256 == "" || s != f.ArchiveSHA256 {
			return nil, fmt.Errorf("%s: контрольная сумма %s, ожидалась %s", f.URL, s, f.ArchiveSHA256)
		}
		archives[f.URL] = zb
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		return nil, err
	}
	for _, zf := range zr.File {
		if zf.Name != f.Member {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxDownload+1))
		rc.Close()
		if err != nil {
			return nil, err
		}
		if s := sum(b); s != f.SHA256 {
			return nil, fmt.Errorf("%s в архиве: контрольная сумма %s, ожидалась %s", f.Member, s, f.SHA256)
		}
		return b, nil
	}
	return nil, fmt.Errorf("в архиве %s нет %s", f.URL, f.Member)
}

// HTTPGetter downloads with client (redirects followed, as GitHub release
// assets need).
func HTTPGetter(ctx context.Context, client *http.Client, userAgent string) Getter {
	return func(url string, max int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: сервер ответил %s", url, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			return nil, fmt.Errorf("%s: загрузка оборвалась: %w", url, err)
		}
		if int64(len(b)) > max {
			return nil, errors.New(url + ": файл больше ожидаемого")
		}
		return b, nil
	}
}

// Verify checks the staged copies: HyRoute's session starter calls it
// before each session.
func Verify(dir string, files []File) error {
	for _, f := range files {
		p := filepath.Join(dir, f.Name)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if sum(b) != f.SHA256 {
			return &MismatchError{Name: f.Name, Path: p}
		}
	}
	return nil
}
