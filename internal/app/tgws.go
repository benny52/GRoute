package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tgws"
	"github.com/lardan099/hyroute/internal/zapret"
)

// «Telegram без VPN» (internal/tgws): a local MTProto proxy on 127.0.0.1
// whose connections go to Telegram over the WebSocket endpoints of its web
// version; when those do not open, through the main VPN server (if HyRoute
// is connected), else straight to the data center. It runs whenever it is
// on, connected or not, as the DPI bypass does. Its settings live in
// zapret.json (zapret.Settings.Telegram) and the «Обход DPI» page.

// tgState is the Controller's part, under zapretMu (tgLive: any
// goroutine, the engine's relay too).
type tgState struct {
	tgProxy  *tgws.Proxy  // nil when its port could not be taken
	tgBridge *tgws.Bridge // runs while it is on
	tgOn     zapret.TelegramSettings
	tgErr    string // why the proxy does not listen
	tgLive   atomic.Pointer[tgws.Bridge]
	tgStop   context.CancelFunc // ends the self-checks
}

// TelegramView is the Telegram part of the page.
type TelegramView struct {
	Enabled bool       `json:"enabled"`
	Port    int        `json:"port"`
	Running bool       `json:"running"` // the proxy listens
	Error   string     `json:"error,omitempty"`
	Link    string     `json:"link,omitempty"` // tg://proxy…, with the secret
	Stats   tgws.Stats `json:"stats"`
	// Health: the latest self-check (nil: none yet).
	Health *tgws.Health `json:"health,omitempty"`
	// Intercepted: HyRoute is connected, so Telegram's own connections
	// reach the bridge without a proxy set in Telegram.
	Intercepted bool `json:"intercepted"`
}

// TelegramInput is what the page saves.
type TelegramInput struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"` // 0 = the default
}

// tgListenAddr is where the proxy listens (a test hook).
var tgListenAddr = func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

// tgBridgeConfig is the bridge's setup (tests replace it).
var tgBridgeConfig = func(c *Controller) tgws.Config {
	// Direct dials as every own connection of HyRoute's (past the rules).
	return tgws.Config{Log: c.Log, VPN: c.tgVPNDial, Dial: c.OwnDial}
}

// tgApplyLocked makes the bridge and the proxy follow the settings. The
// bridge runs while the switch is on (the engine's interception needs no
// port); the proxy listens when its port is free.
func (c *Controller) tgApplyLocked() {
	want := c.zapretCfg.Telegram
	if c.zapretErr != nil {
		want.Enabled = false
	}
	if c.tgBridge != nil && want.Enabled && want == c.tgOn && c.tgProxy != nil {
		return
	}
	if c.tgBridge != nil && want.Enabled && want == c.tgOn {
		c.tgListenLocked(want) // the port may be free now
		return
	}
	if c.tgBridge != nil {
		if c.tgProxy != nil {
			c.tgProxy.Close()
		}
		c.tgStop()
		c.tgLive.Store(nil)
		c.tgBridge.Close()
		c.tgProxy, c.tgBridge, c.tgStop = nil, nil, nil
		c.Log.Info("tgws: stopped")
	}
	c.tgOn, c.tgErr = want, ""
	if !want.Enabled {
		return
	}
	c.tgBridge = tgws.New(tgBridgeConfig(c))
	c.tgBridge.Warm()
	c.tgLive.Store(c.tgBridge)
	ctx, cancel := context.WithCancel(context.Background())
	c.tgStop = cancel
	go c.tgChecks(ctx, c.tgBridge)
	c.tgListenLocked(want)
}

// tgListenLocked starts the proxy on its port.
func (c *Controller) tgListenLocked(want zapret.TelegramSettings) {
	secret, err := hex.DecodeString(want.Secret)
	if err != nil || len(secret) != 16 {
		c.tgErr = "секрет прокси не задан"
		return
	}
	p := &tgws.Proxy{Bridge: c.tgBridge, Secret: secret}
	if err := p.Listen(tgListenAddr(want.TelegramPort())); err != nil {
		if c.tgErr == "" {
			c.Log.Warn("tgws: proxy not started", "err", err)
		}
		c.tgErr = fmt.Sprintf("порт %d занят (запущен tg-ws-proxy или другая программа?): %v", want.TelegramPort(), err)
		return
	}
	c.tgProxy, c.tgErr = p, ""
	c.Log.Info("tgws: proxy listening", "port", want.TelegramPort())
}

// Test hooks: when the self-checks run.
var (
	tgCheckFirst = 5 * time.Second
	tgCheckEvery = 5 * time.Minute
)

// tgChecks runs the bridge's self-checks while it runs: a WebSocket that
// stops answering is skipped (Telegram goes through the VPN or directly
// at once), one that answers again is used again.
func (c *Controller) tgChecks(ctx context.Context, b *tgws.Bridge) {
	t := time.NewTimer(tgCheckFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		before := b.Health()
		h := b.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		if before == nil || before.WS != h.WS || before.Fallback != h.Fallback {
			c.Log.Info("tgws: self-check", "websocket", h.WS, "route", h.WSRoute, "fallback", h.Fallback)
		}
		c.changed()
		t.Reset(tgCheckEvery)
	}
}

// tgSession gives a session the engine's route to the bridge.
func (c *Controller) tgSession(cfg *session.Config) {
	if cfg.Extra == nil {
		cfg.Extra = map[string]session.ExtraTunnel{}
	}
	cfg.Extra[tgws.ProfileID] = tgws.Tunnel{Get: c.tgLive.Load}
}

// telegramRule is the rule «Обход DPI: Telegram»: Telegram's addresses
// go to the bridge; when it does not run, through the main server.
func telegramRule() rules.Rule {
	return rules.Rule{Name: ZapretRulePrefix + "Telegram", Domains: slices.Clone(tgws.Networks), Protocol: "tcp",
		Ports: rules.PortList(slices.Clone(tgws.Ports)), Action: rules.Tunnel, Profile: tgws.ProfileID, Fallback: []string{""}}
}

// tgVPNDial reaches a data center through the main server when HyRoute is
// connected (the bridge's fallback before a direct connection).
func (c *Controller) tgVPNDial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	c.mu.Lock()
	s := c.sess
	id := c.mainTargetLocked()
	c.mu.Unlock()
	if s == nil || id == "" {
		return nil, errors.New("HyRoute не подключён")
	}
	if groups.IsGroupID(id) {
		id = c.groupMemberFor(id)
	}
	ep := s.Endpoint(id)
	if ep == nil || !ep.Available() {
		return nil, errors.New("основной сервер не подключён")
	}
	return ep.Dial(ctx, socks5.AddrFromAddrPort(dst))
}

// groupMemberFor: the member a group sends through now ("" when none).
func (c *Controller) groupMemberFor(gid string) string {
	for _, g := range c.Groups().Groups {
		if g.ID == gid {
			return g.Active
		}
	}
	return ""
}

func (c *Controller) telegramViewLocked() TelegramView {
	t := c.zapretCfg.Telegram
	v := TelegramView{Enabled: t.Enabled, Port: t.TelegramPort(), Error: c.tgErr}
	if c.tgBridge != nil {
		v.Stats, v.Health = c.tgBridge.Stats(), c.tgBridge.Health()
		c.mu.Lock()
		v.Intercepted = c.sess != nil
		c.mu.Unlock()
	}
	if c.tgProxy != nil {
		v.Running = true
		if secret, err := hex.DecodeString(c.tgOn.Secret); err == nil {
			v.Link = tgws.Link("127.0.0.1", c.tgOn.TelegramPort(), secret)
		}
	}
	return v
}

// SaveTelegram turns the proxy on or off.
func (c *Controller) SaveTelegram(in TelegramInput) error {
	if in.Port != 0 && (in.Port < 1024 || in.Port > 65535) {
		return errors.New("порт — от 1024 до 65535")
	}
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	if c.zapretErr != nil {
		return fmt.Errorf("zapret.json не загружен, изменения не сохраняются: %v", c.zapretErr)
	}
	next := cloneZapretSettings(c.zapretCfg)
	next.Telegram.Enabled, next.Telegram.Port = in.Enabled, in.Port
	if next.Telegram.Port == zapret.DefaultTelegramPort {
		next.Telegram.Port = 0
	}
	if next.Telegram.Secret == "" {
		next.Telegram.Secret = hex.EncodeToString(tgws.NewSecret())
	}
	if err := c.Store.SaveZapret(next); err != nil {
		return err
	}
	c.zapretCfg = next
	c.Log.Info("tgws: settings saved", "on", in.Enabled)
	c.zapretApplyLocked() // the rule «Обход DPI: Telegram», the bridge
	c.changed()
	if in.Enabled && c.tgErr != "" {
		return errors.New(c.tgErr)
	}
	return nil
}

// TelegramLink is the tg://proxy link (the page's «Подключить» and
// «Скопировать»); "" when the proxy does not run.
func (c *Controller) TelegramLink() string {
	c.zapretMu.Lock()
	defer c.zapretMu.Unlock()
	return c.telegramViewLocked().Link
}
