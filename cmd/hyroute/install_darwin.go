//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The service's files: its own copy of HyRoute and the cores, in a folder
// only root may write to (launchd runs it as root: a copy any user could
// replace would hand out root).
const (
	serviceLabel = "com.hyroute.service"
	serviceDir   = "/Library/Application Support/HyRoute/bin"
	servicePlist = "/Library/LaunchDaemons/" + serviceLabel + ".plist"
	serviceLog   = "/Library/Logs/HyRoute-service.log"
)

const plistText = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + serviceLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + serviceDir + `/HyRoute</string>
		<string>--daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>` + serviceLog + `</string>
</dict>
</plist>
`

// installService (as root, through the administrator prompt) copies
// HyRoute and the cores out of the app bundle and (re)starts the service.
func installService() error {
	if os.Geteuid() != 0 {
		return errors.New("нужны права администратора")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	res := filepath.Join(filepath.Dir(filepath.Dir(exe)), "Resources")
	// Stop the old service first: its files are replaced.
	exec.Command("/bin/launchctl", "bootout", "system/"+serviceLabel).Run()
	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		return err
	}
	for _, d := range []string{"/Library/Application Support/HyRoute", serviceDir} {
		if err := os.Chown(d, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
	}
	files := map[string]string{"HyRoute": exe, "hysteria": filepath.Join(res, "hysteria"), "xray": filepath.Join(res, "xray")}
	for name, src := range files {
		if err := copyRootFile(src, filepath.Join(serviceDir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := os.WriteFile(servicePlist, []byte(plistText), 0o644); err != nil {
		return err
	}
	os.Chown(servicePlist, 0, 0)
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", servicePlist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyRootFile writes a root-owned executable copy, replacing dst whole
// (never writing through a link someone left in its place).
func copyRootFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	os.Chown(tmp, 0, 0)
	// Downloaded apps carry the quarantine flag: launchd would not start
	// the copy.
	exec.Command("/usr/bin/xattr", "-d", "com.apple.quarantine", tmp).Run()
	return os.Rename(tmp, dst)
}

// uninstallService stops the service and removes its files (the data in
// root's folder stays).
func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("нужны права администратора")
	}
	exec.Command("/bin/launchctl", "bootout", "system/"+serviceLabel).Run()
	os.Remove(servicePlist)
	return os.RemoveAll(serviceDir)
}

// asAdmin runs this program with args as root after macOS asks for an
// administrator's password.
func asAdmin(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := shellQuote(exe)
	for _, a := range args {
		cmd += " " + shellQuote(a)
	}
	script := `do shell script "` + strings.ReplaceAll(cmd, `"`, `\"`) + `" with administrator privileges with prompt "HyRoute устанавливает свою службу: она направляет трафик Mac через выбранные серверы."`
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "-128") {
			return errors.New("установка службы отменена")
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
