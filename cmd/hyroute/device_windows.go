//go:build windows

package main

import (
	"golang.org/x/sys/windows/registry"

	"github.com/lardan099/hyroute/internal/app"
)

// deviceInfo is this computer for a subscription panel at host
// (app.DeviceInfo): an ID from Windows' MachineGuid (app.DeviceID hashes it
// with the host), the Windows version and no model or computer name.
func deviceInfo(host string) app.DeviceInfo {
	return app.DeviceInfo{HWID: app.DeviceID(machineGUID(), host), OS: "Windows", OSVersion: windowsVersion(), Model: "PC"}
}

// machineGUID is HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid ("" if
// unreadable), the 64-bit view whatever the process.
func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return v
}
