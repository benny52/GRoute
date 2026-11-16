//go:build !windows

package session

import (
	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/tunnels"
)

func newAWGRunner(cfg Config, p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
	return awg.NewRunner(p, h)
}
