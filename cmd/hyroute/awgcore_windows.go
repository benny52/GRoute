package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/runtimefiles"
	"golang.org/x/sys/windows/registry"
)

// The portable packager records the digest of the helper it ships.
var bundledAWGSHA256 string

func approvedAWGHash() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\GRoute\Cores`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, _ := key.GetStringValue("AmneziaWGSHA256")
	return strings.TrimSpace(value)
}

// Multiple profiles may start together. Stage each approved version into its
// own directory, so running tunnels keep their binary until they stop.
func awgExecutable(src, runtimeDir, bundled string, approved func() string, protect func(string) error) func() (string, error) {
	var mu sync.Mutex
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		const name = "groute-awg.exe"
		file, err := os.Open(filepath.Join(src, name))
		if err != nil {
			return "", fmt.Errorf("открыть %s рядом с GRoute.exe: %w", name, err)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			return "", err
		}
		digest := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(digest, bundled) && !strings.EqualFold(digest, approved()) {
			return "", fmt.Errorf("версия %s не подтверждена: проверьте SHA-256 выпуска (см. руководство GRoute)", name)
		}
		dir := filepath.Join(runtimeDir, "awg-"+digest)
		if err := protect(dir); err != nil {
			return "", err
		}
		_, err = runtimefiles.Stage(src, dir, []runtimefiles.File{{Name: name, SHA256: digest}}, nil)
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, name), nil
	}
}
