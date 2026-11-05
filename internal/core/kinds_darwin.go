//go:build darwin

package core

import "runtime"

// On macOS the cores are the darwin builds of the Mac's own architecture
// (the service runs the slice of the universal binary that fits it).
func init() {
	Hysteria.Exe = "hysteria"
	Hysteria.Asset = "hysteria-darwin-" + runtime.GOARCH
	Xray.Exe, Xray.Member = "xray", "xray"
	Xray.Asset = "Xray-macos-64.zip"
	if runtime.GOARCH == "arm64" {
		Xray.Asset = "Xray-macos-arm64-v8a.zip"
	}
}
