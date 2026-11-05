//go:build darwin && cgo

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/lardan099/hyroute/frontend"
	"github.com/lardan099/hyroute/internal/uirpc"
)

// Bridge is bound to the page: window.go.main.Bridge (frontend/src/api.ts),
// as on Windows. Its calls go to the service over the socket.
type Bridge struct {
	peer    *uirpc.Peer
	ctx     atomic.Pointer[context.Context]
	unsaved atomic.Int32
	closing atomic.Bool
}

func (b *Bridge) Call(method string, args []json.RawMessage) (json.RawMessage, error) {
	r, err := b.peer.CallRaw(context.Background(), method, args)
	if errors.Is(err, uirpc.ErrClosed) {
		return nil, errors.New("нет связи со службой HyRoute")
	}
	return r, err
}

func (b *Bridge) SetUnsaved(n int) { b.unsaved.Store(int32(n)) }

func (b *Bridge) context() context.Context {
	if p := b.ctx.Load(); p != nil {
		return *p
	}
	return nil
}

// connectService connects to the service, installing it first (the
// administrator's password) when it is missing or of another version.
func connectService() (*uirpc.Peer, error) {
	c, err := net.Dial("unix", sockPath)
	installed := false
	if err != nil {
		if err := asAdmin("--install-service"); err != nil {
			return nil, err
		}
		installed = true
		if c, err = waitService(); err != nil {
			return nil, err
		}
	}
	p := uirpc.New(c, c)
	refused := make(chan string, 1)
	p.OnEvent = func(name string, args []json.RawMessage) {
		if name == "refused" && len(args) > 0 {
			var s string
			json.Unmarshal(args[0], &s)
			refused <- s
		}
	}
	go p.Run()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := p.Call(ctx, "ServiceVersion")
	select {
	case msg := <-refused:
		return nil, errors.New(msg)
	default:
	}
	if err != nil {
		return nil, fmt.Errorf("служба HyRoute не отвечает: %w", err)
	}
	var v string
	json.Unmarshal(r, &v)
	if v != version+" "+build && !installed {
		// Another version: this app's copy replaces it.
		c.Close()
		if err := asAdmin("--install-service"); err != nil {
			return nil, err
		}
		return connectService()
	}
	return p, nil
}

func waitService() (net.Conn, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.Dial("unix", sockPath)
		if err == nil {
			return c, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("служба HyRoute не запустилась (журнал: %s): %w", serviceLog, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func alert(text string) {
	script := `display alert "HyRoute" message "` + strings.ReplaceAll(strings.ReplaceAll(text, `\`, `\\`), `"`, `\"`) + `" as critical`
	exec.Command("/usr/bin/osascript", "-e", script).Run()
}

// runWindow is HyRoute.app: the window of the service.
func runWindow() {
	peer, err := connectService()
	if err != nil {
		alert(err.Error())
		os.Exit(1)
	}
	go startMenubar()
	b := &Bridge{peer: peer}
	peer.OnCall = b.answer
	peer.OnEvent = func(name string, args []json.RawMessage) {
		ctx := b.context()
		if ctx == nil {
			return
		}
		data := make([]any, len(args))
		for i, a := range args {
			json.Unmarshal(a, &data[i])
		}
		runtime.EventsEmit(ctx, name, data...)
	}
	go func() {
		<-peer.Done()
		// The service is gone (stopped, restarted by launchd).
		if b.closing.Load() {
			return
		}
		alert("Связь со службой HyRoute потеряна. Откройте HyRoute снова.")
		if ctx := b.context(); ctx != nil {
			runtime.Quit(ctx)
		}
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}()
	err = wails.Run(&options.App{
		Title:            "HyRoute",
		Width:            1180,
		Height:           760,
		MinWidth:         900,
		MinHeight:        560,
		BackgroundColour: &options.RGBA{R: 24, G: 26, B: 31, A: 255},
		AssetServer:      &assetserver.Options{Assets: frontend.Dist},
		LogLevel:         logger.ERROR,
		OnStartup: func(ctx context.Context) {
			b.ctx.Store(&ctx)
		},
		OnDomReady: func(ctx context.Context) {
			peer.Notify("window.ready")
		},
		OnBeforeClose: func(ctx context.Context) bool {
			if n := b.unsaved.Load(); n > 0 && !b.closing.Load() {
				r, _ := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
					Type: runtime.QuestionDialog, Title: "HyRoute",
					Message:       "Есть несохранённые изменения. Закрыть окно и потерять их?",
					Buttons:       []string{"Закрыть", "Отмена"},
					DefaultButton: "Отмена",
				})
				if r != "Закрыть" && r != "Yes" {
					return true
				}
			}
			b.closing.Store(true)
			return false
		},
		Bind: []any{b},
		Mac: &mac.Options{
			Appearance: mac.DefaultAppearance,
			About:      &mac.AboutInfo{Title: "HyRoute", Message: version},
		},
	})
	if err != nil {
		alert(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

// answer serves the service's calls: what needs the window or the user's
// session.
func (b *Bridge) answer(method string, args []json.RawMessage) (any, error) {
	ctx := b.context()
	if ctx == nil {
		return nil, errors.New("окно ещё открывается")
	}
	arg := func(i int, v any) error {
		if i >= len(args) {
			return fmt.Errorf("%s: нет аргумента %d", method, i+1)
		}
		return json.Unmarshal(args[i], v)
	}
	switch method {
	case "show":
		runtime.WindowShow(ctx)
		return nil, nil
	case "close":
		b.closing.Store(true)
		runtime.Quit(ctx)
		return nil, nil
	case "clipboard.get":
		return runtime.ClipboardGetText(ctx)
	case "clipboard.set":
		var s string
		if err := arg(0, &s); err != nil {
			return nil, err
		}
		return nil, runtime.ClipboardSetText(ctx, s)
	case "dialog.open":
		var o runtime.OpenDialogOptions
		if err := arg(0, &o); err != nil {
			return nil, err
		}
		return runtime.OpenFileDialog(ctx, o)
	case "dialog.save":
		var o runtime.SaveDialogOptions
		if err := arg(0, &o); err != nil {
			return nil, err
		}
		return runtime.SaveFileDialog(ctx, o)
	case "reveal":
		// The browser extension's folder, in Finder.
		var p string
		if err := arg(0, &p); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(p, "/Library/Application Support/HyRoute/") {
			return nil, errors.New("показываются только папки HyRoute")
		}
		return nil, exec.Command("/usr/bin/open", "-R", p).Run()
	case "open.browser":
		var app, page string
		if err := arg(0, &app); err != nil {
			return nil, err
		}
		if err := arg(1, &page); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(app, "/Applications/") || !strings.HasSuffix(app, ".app") || !strings.HasSuffix(page, "://extensions/") {
			return nil, errors.New("открывается только страница расширений браузера")
		}
		return nil, exec.Command("/usr/bin/open", "-a", app, page).Run()
	case "open":
		var s string
		if err := arg(0, &s); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
			return nil, errors.New("открываются только ссылки http и https")
		}
		runtime.BrowserOpenURL(ctx, s)
		return nil, nil
	}
	return nil, fmt.Errorf("окно не знает вызова %q", method)
}
