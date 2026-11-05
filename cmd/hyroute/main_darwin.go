//go:build darwin

// HyRoute for macOS: the service (--daemon, root, launchd) and the window
// (HyRoute.app, the user's).
package main

import (
	"flag"
	"fmt"
	"os"
)

// Stamped by the build: build is the git commit, version the release tag.
var (
	build      = "dev"
	version    = "v0.0.0-dev"
	updateRepo = "lardan099/HyRoute"
)

func main() {
	daemon := flag.Bool("daemon", false, "be the service (launchd starts it as root)")
	install := flag.Bool("install-service", false, "install and start the service (root)")
	uninstall := flag.Bool("uninstall-service", false, "stop and remove the service (root)")
	stub := flag.Bool("stub", false, "service: an in-process SOCKS5 stub instead of Hysteria (testing)")
	verbose := flag.Bool("v", false, "service: debug logging")
	flag.Parse()
	switch {
	case *daemon:
		runDaemon(*verbose, *stub)
	case *install:
		if err := installService(); err != nil {
			fmt.Fprintln(os.Stderr, "HyRoute:", err)
			os.Exit(1)
		}
	case *uninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintln(os.Stderr, "HyRoute:", err)
			os.Exit(1)
		}
	default:
		runWindow()
	}
}
