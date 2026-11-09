package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/lardan099/hyroute/internal/groups"
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

// tgState is the Controller's part, under zapretMu.
type tgState struct {
	tgProxy  *tgws.Proxy
	tgBridge *tgws.Bridge
	tgOn     zapret.TelegramSettings // what runs now
	tgErr    string                  // why it does not
}

// TelegramView is the Telegram part of the page.
type TelegramView struct {
	Enabled bool       `json:"enabled"`
	Port    int        `json:"port"`
	Running bool       `json:"running"`
	Error   string     `json:"error,omitempty"`
	Link    string     `json:"link,omitempty"` // tg://proxy…, with the secret
	Stats   tgws.Stats `json:"stats"`
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

// tgApplyLocked makes the proxy follow the settings.
func (c *Controller) tgApplyLocked() {
	want := c.zapretCfg.Telegram
	if c.zapretErr != nil {
		want.Enabled = false
	}
	if c.tgProxy != nil && want.Enabled && want == c.tgOn {
		return
	}
	if c.tgProxy != nil {
		c.tgProxy.Close()
		c.tgBridge.Close()
		c.tgProxy, c.tgBridge = nil, nil
		c.Log.Info("tgws: proxy stopped")
	}
	c.tgOn, c.tgErr = want, ""
	if !want.Enabled {
		return
	}
	secret, err := hex.DecodeString(want.Secret)
	if err != nil || len(secret) != 16 {
		c.tgErr = "секрет прокси не задан"
		return
	}
	b := tgws.New(tgBridgeConfig(c))
	p := &tgws.Proxy{Bridge: b, Secret: secret}
	if err := p.Listen(tgListenAddr(want.TelegramPort())); err != nil {
		b.Close()
		c.tgErr = fmt.Sprintf("порт %d занят (запущен tg-ws-proxy или другая программа?): %v", want.TelegramPort(), err)
		c.Log.Warn("tgws: proxy not started", "err", err)
		return
	}
	b.Warm()
	c.tgProxy, c.tgBridge = p, b
	c.Log.Info("tgws: proxy listening", "port", want.TelegramPort())
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
	if c.tgProxy != nil {
		v.Running = true
		v.Stats = c.tgBridge.Stats()
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
	c.tgApplyLocked()
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
