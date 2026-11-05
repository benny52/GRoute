//go:build darwin

package core

import "runtime"

// MacKinds are the cores for macOS: the darwin builds of the Mac's own
// architecture (the service runs the slice of the universal binary that
// fits it).
func MacKinds() (hysteria, xray Kind) {
	hysteria, xray = Hysteria, Xray
	hysteria.Exe = "hysteria"
	hysteria.Asset = "hysteria-darwin-" + runtime.GOARCH
	xray.Exe, xray.Member = "xray", "xray"
	xray.Asset = "Xray-macos-64.zip"
	if runtime.GOARCH == "arm64" {
		xray.Asset = "Xray-macos-arm64-v8a.zip"
	}
	return hysteria, xray
}
