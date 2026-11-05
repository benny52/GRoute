package hysteria

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var versionRe = regexp.MustCompile(`(?m)^Version:\s*(\S+)`)

// ExeVersion runs "hysteria version" and returns the version ("v2.12.3").
// A binary that does not answer like Hysteria is an error: this doubles as
// the "does the new core start at all" check.
func ExeVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = append(cmd.Environ(), "HYSTERIA_DISABLE_UPDATE_CHECK=1")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	m := versionRe.FindSubmatch(out)
	if m == nil {
		return "", errors.New("не похоже на hysteria: нет строки Version")
	}
	return string(m[1]), nil
}

var xrayVersionRe = regexp.MustCompile(`(?m)^Xray (\d+\.\d+\.\d+)\b`)

// XrayVersion runs "xray version" and returns the version ("v26.10.31"),
// from its first line: "Xray 26.10.31 (Xray, Penetrates Everything.) …".
func XrayVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return parseXrayVersion(out)
}

func parseXrayVersion(out []byte) (string, error) {
	m := xrayVersionRe.FindSubmatch(out)
	if m == nil {
		return "", errors.New("не похоже на xray: нет строки «Xray <версия>»")
	}
	return "v" + string(m[1]), nil
}

// XrayTest has the xray.exe at path check cfg without starting it ("xray
// run -test"): the config goes in on stdin, so the user ID never touches
// the disk. The error is Xray's own reason.
func XrayTest(path string, cfg []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "run", "-test", "-format", "json", "-c", "stdin:")
	cmd.Stdin = bytes.NewReader(cfg)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	return errors.New(xrayTestReason(out, err))
}

// xrayTestReason is the line of Xray's output that says what is wrong
// ("Failed to start: …"), else its last line, else err.
func xrayTestReason(out []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, l := range lines {
		if r, ok := strings.CutPrefix(strings.TrimSpace(l), "Failed to start:"); ok {
			return strings.TrimSpace(r)
		}
	}
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	return err.Error()
}
