package awgcore

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// The older portable prototype printed the upstream library version only.
// It predates every independently versioned release of the GRoute helper.
var awgVersionLine = regexp.MustCompile(`^groute-awg (v[0-9]+\.[0-9]+\.[0-9]+)(?: engine=(v[0-9]+\.[0-9]+\.[0-9]+))? ipc=([0-9]+)$`)

type awgVersions struct{ helper, engine string }

func probeAWG(path string) (awgVersions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return awgVersions{}, fmt.Errorf("groute-awg.exe --version: %w", err)
	}
	return parseAWGVersion(string(out))
}

func parseAWGVersion(output string) (awgVersions, error) {
	line := awgVersionLine.FindStringSubmatch(strings.TrimSpace(output))
	if line == nil {
		return awgVersions{}, fmt.Errorf("файл не сообщил версию groute-awg")
	}
	if line[3] != fmt.Sprint(Protocol) {
		return awgVersions{}, fmt.Errorf("этому GRoute требуется протокол обмена %d, ядро использует %s", Protocol, line[3])
	}
	if line[2] == "" {
		return awgVersions{"v0.0.0", line[1]}, nil
	}
	return awgVersions{line[1], line[2]}, nil
}

func HelperVersion(path string) (string, error) {
	versions, err := probeAWG(path)
	return versions.helper, err
}

func EngineVersion(path string) (string, error) {
	versions, err := probeAWG(path)
	return versions.engine, err
}
