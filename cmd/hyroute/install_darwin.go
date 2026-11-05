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
	"time"

	"github.com/lardan099/hyroute/internal/killswitch"
)

// The service's files: its own copy of HyRoute and the cores, in a folder
// only root may write to (launchd runs it as root: a copy any user could
// replace would hand out root).
const (
	serviceLabel = "com.hyroute.service"
	serviceDir   = "/Library/Application Support/HyRoute/bin"
	// appStageDir holds a readable copy of the HyRoute.app the service was
	// updated to: the window replaces its own app from it when the
	// service may not (stageAppCopy).
	appStageDir  = "/Library/Application Support/HyRoute/app"
	servicePlist = "/Library/LaunchDaemons/" + serviceLabel + ".plist"
	serviceLog   = "/Library/Logs/HyRoute-service.log"
	menubarLabel = "com.hyroute.menubar"
	menubarPlist = "/Library/LaunchAgents/" + menubarLabel + ".plist"
)

// menubarText: the menu bar icon, for every user who signs in.
const menubarText = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + menubarLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + serviceDir + `/HyRoute</string>
		<string>--menubar</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`

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
	// The kill switch lets the sockets of this group through: the service
	// and its cores run with it.
	if _, err := killswitch.EnsureGroup(); err != nil {
		return err
	}
	// Stop the old service first: its files are replaced. bootout may
	// return before the job is gone; it is waited for.
	exec.Command("/bin/launchctl", "bootout", "system/"+serviceLabel).Run()
	waitUnloaded(10 * time.Second)
	if err := installFiles(exe, res); err != nil {
		return err
	}
	if err := os.WriteFile(servicePlist, []byte(plistText), 0o644); err != nil {
		return err
	}
	os.Chown(servicePlist, 0, 0)
	if err := startService(); err != nil {
		return err
	}
	// The menu bar icon: for every user at login, and now for the one at
	// the screen (its old copy goes first).
	if err := os.WriteFile(menubarPlist, []byte(menubarText), 0o644); err != nil {
		return err
	}
	os.Chown(menubarPlist, 0, 0)
	if uid := consoleUID(); uid != "" {
		exec.Command("/bin/launchctl", "bootout", "gui/"+uid+"/"+menubarLabel).Run()
		exec.Command("/bin/launchctl", "bootstrap", "gui/"+uid, menubarPlist).Run()
	}
	return nil
}

// serviceLoaded reports that launchd holds the service's job.
func serviceLoaded() bool {
	return exec.Command("/bin/launchctl", "print", "system/"+serviceLabel).Run() == nil
}

func waitUnloaded(d time.Duration) {
	for deadline := time.Now().Add(d); serviceLoaded() && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond)
	}
}

// startService loads the service's job. bootstrap fails ("5: Input/output
// error") while a job of that label is still loaded: an old one going
// away is waited for, and one that stays is restarted from the new files
// (kickstart -k) instead.
func startService() error {
	exec.Command("/bin/launchctl", "enable", "system/"+serviceLabel).Run() // a disabled job does not load
	var last error
	for try := 0; try < 3; try++ {
		out, err := exec.Command("/bin/launchctl", "bootstrap", "system", servicePlist).CombinedOutput()
		if err == nil {
			return nil
		}
		last = fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
		if serviceLoaded() {
			out, err := exec.Command("/bin/launchctl", "kickstart", "-k", "system/"+serviceLabel).CombinedOutput()
			if err == nil {
				return nil
			}
			last = fmt.Errorf("launchctl kickstart: %v: %s", err, strings.TrimSpace(string(out)))
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("служба HyRoute не запустилась (журнал: %s): %w", serviceLog, last)
}

// installFiles copies HyRoute (exe) and the cores and hyroutectl (from
// the bundle's Resources, res) into the service's folder, and links
// hyroutectl on the PATH. Used by the install and by an update, which the
// running service applies itself before launchd restarts it.
func installFiles(exe, res string) error {
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
	files := map[string]string{"HyRoute": exe, "hysteria": filepath.Join(res, "hysteria"), "xray": filepath.Join(res, "xray"),
		"hyroutectl": filepath.Join(res, "hyroutectl")}
	for name, src := range files {
		if err := copyRootFile(src, filepath.Join(serviceDir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	// hyroutectl on the PATH (a link to the service's copy).
	if os.MkdirAll(filepath.Dir(hyroutectlLink), 0o755) == nil {
		if cur, err := os.Readlink(hyroutectlLink); err == nil || os.IsNotExist(err) {
			if err == nil && cur != filepath.Join(serviceDir, "hyroutectl") {
				// Someone else's hyroutectl: left alone.
			} else {
				os.Remove(hyroutectlLink)
				os.Symlink(filepath.Join(serviceDir, "hyroutectl"), hyroutectlLink)
			}
		}
	}
	return nil
}

// consoleUID is the user signed in at the screen ("" for none).
func consoleUID() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%u", "/dev/console").Output()
	uid := strings.TrimSpace(string(out))
	if err != nil || uid == "" || uid == "0" {
		return ""
	}
	return uid
}

// startMenubar (the window, as its user) brings the menu bar icon back
// when it was hidden («Скрыть значок»).
func startMenubar() {
	uid := fmt.Sprint(os.Getuid())
	if exec.Command("/bin/launchctl", "kickstart", "gui/"+uid+"/"+menubarLabel).Run() != nil {
		exec.Command("/bin/launchctl", "bootstrap", "gui/"+uid, menubarPlist).Run()
	}
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
	if uid := consoleUID(); uid != "" {
		exec.Command("/bin/launchctl", "bootout", "gui/"+uid+"/"+menubarLabel).Run()
	}
	os.Remove(menubarPlist)
	os.RemoveAll(appStageDir)
	if cur, err := os.Readlink(hyroutectlLink); err == nil && cur == filepath.Join(serviceDir, "hyroutectl") {
		os.Remove(hyroutectlLink)
	}
	// A block the service left (it stopped while connected) goes too.
	(&killswitch.Switch{StateDir: filepath.Join("/var/root/Library/Application Support/HyRoute")}).Release()
	killswitch.DeleteGroup()
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
