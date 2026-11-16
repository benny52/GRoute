//go:build windows

package session

import (
	"path/filepath"

	"github.com/lardan099/hyroute/internal/awgcore"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/tunnels"
)

func newAWGRunner(cfg Config, p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
	path := cfg.AWG
	if path == nil {
		path = func() (string, error) { return filepath.Join(cfg.Dir, "groute-awg.exe"), nil }
	}
	return awgcore.NewRunner(path, p, h)
}
