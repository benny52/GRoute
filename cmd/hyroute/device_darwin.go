//go:build darwin

package main

import (
	"os/exec"
	"regexp"

	"github.com/lardan099/hyroute/internal/app"
)

// deviceInfo is this Mac for a subscription panel at host (app.DeviceInfo):
// an ID from the hardware UUID (hashed with the host), the macOS version
// and "Mac" for the model.
func deviceInfo(host string) app.DeviceInfo {
	return app.DeviceInfo{HWID: app.DeviceID(platformUUID(), host), OS: "macOS", OSVersion: macVersion(), Model: "Mac"}
}

var uuidRe = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`)

func platformUUID() string {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	if m := uuidRe.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}
