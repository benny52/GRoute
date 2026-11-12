package main

import (
	"errors"
	"path/filepath"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/store"
)

// Stamped only in the portable Windows archive (-X main.portableBuild=true).
var portableBuild = "false"

func isPortableBuild() bool { return portableBuild == "true" }

type windowsPaths struct {
	data       string
	components string
	instance   string
}

func pathsForBuild(exe string, portable, elevated bool) (windowsPaths, error) {
	if portable {
		if !filepath.IsAbs(exe) {
			return windowsPaths{}, errors.New("не удалось определить папку GRoute.exe")
		}
		data := filepath.Join(filepath.Dir(exe), "Data")
		components := filepath.Join(data, "Components")
		if elevated {
			// ProtectDir secures the component directory and its parent.
			// Elevated binaries must never come from the user's writable Data.
			components = core.ProductDir("GRoute")
		}
		return windowsPaths{data, components, "GRoute-portable-8c5b43d2"}, nil
	}
	data, err := store.DefaultDir()
	return windowsPaths{data, core.DefaultDir(""), instanceID}, err
}
