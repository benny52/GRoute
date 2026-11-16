// Command groute-awg runs one AmneziaWG profile for GRoute over private
// inherited pipes. No keys, proxy passwords, or profile paths are in argv.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/awgcore"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// A GRoute helper can change without an upstream protocol-library release.
// Stamp separate releases with -X main.helperVersion=vX.Y.Z.
var helperVersion = "v1.0.0"

func engineVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, mod := range info.Deps {
			if mod.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
				return mod.Version
			}
		}
	}
	return "unknown"
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("groute-awg %s engine=%s ipc=%d\n", helperVersion, engineVersion(), awgcore.Protocol)
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--serve" {
		fmt.Fprintln(os.Stderr, "Использование: groute-awg --version | --serve")
		os.Exit(2)
	}
	if !serve(os.Stdin, os.Stdout) {
		os.Exit(1)
	}
}

func serve(in io.Reader, out io.Writer) bool {
	enc := json.NewEncoder(out)
	if err := enc.Encode(awgcore.Event{Type: "hello", Version: awgcore.Protocol}); err != nil {
		return false
	}
	reader := awgcore.Reader(in)
	var req awgcore.Request
	if err := awgcore.Read(reader, &req); err != nil {
		return false
	}
	p, err := hysteria.ParseAWGConfig(req.Config)
	if err != nil {
		_ = enc.Encode(awgcore.Event{Type: "error", Status: hysteria.Status{
			State: hysteria.Failed, Kind: hysteria.ErrOther, Message: "AmneziaWG: недопустимые параметры профиля",
		}})
		return false
	}

	// Emit ready (including the private proxy credentials) before any live
	// transition. The monitor may already have published a handshake.
	var mu sync.Mutex
	var ready bool
	r := awg.NewRunner(p, tunnels.Hooks{OnStatus: func(st hysteria.Status) {
		mu.Lock()
		defer mu.Unlock()
		if ready {
			_ = enc.Encode(awgcore.Event{Type: "status", Status: st})
		}
	}})
	if err := r.Start(); err != nil {
		_ = enc.Encode(awgcore.Event{Type: "error", Status: r.Status()})
		return false
	}
	defer r.Stop()
	mu.Lock()
	proxy := r.SOCKS()
	err = enc.Encode(awgcore.Event{Type: "ready", Status: r.Status(), Username: proxy.Username, Password: proxy.Password})
	ready = err == nil
	mu.Unlock()
	if err != nil {
		return false
	}
	// Parent keeps its input pipe open as a lifetime lease.
	_, err = reader.ReadByte()
	return err == io.EOF
}
