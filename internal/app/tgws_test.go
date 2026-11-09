package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tgws"
	"github.com/lardan099/hyroute/internal/zapret"
)

// «Telegram без VPN»: on, the proxy listens with a secret of its own kept
// in zapret.json; a busy port is said; off stops it; the setting survives
// a restart of the controller.
func TestTelegramProxy(t *testing.T) {
	c, _ := newCtl(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	noTelegramNet(t)

	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: port}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.SaveTelegram(TelegramInput{}) })
	v := c.ZapretInfo().Telegram
	if !v.Running || v.Port != port || !strings.HasPrefix(v.Link, "tg://proxy?port="+strconv.Itoa(port)+"&secret=dd") || c.TelegramLink() != v.Link {
		t.Fatalf("%+v", v)
	}
	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	} else {
		conn.Close()
	}
	cfg, _ := c.Store.LoadZapret()
	secret := cfg.Telegram.Secret
	if len(secret) != 32 || !strings.Contains(v.Link, "dd"+secret) {
		t.Fatalf("%+v", cfg.Telegram)
	}
	// Saved again: the same secret (Telegram keeps the proxy it added).
	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: port}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := c.Store.LoadZapret(); cfg.Telegram.Secret != secret {
		t.Fatal("secret changed")
	}
	// Off: nothing listens.
	if err := c.SaveTelegram(TelegramInput{}); err != nil {
		t.Fatal(err)
	}
	if v := c.ZapretInfo().Telegram; v.Running || v.Link != "" || c.TelegramLink() != "" {
		t.Fatalf("%+v", v)
	}
	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		conn.Close()
		t.Fatal("still listening")
	}
	// A port taken by another program: said, not running.
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	bp := busy.Addr().(*net.TCPAddr).Port
	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: bp}); err == nil || !strings.Contains(err.Error(), "занят") {
		t.Fatalf("%v", err)
	}
	if v := c.ZapretInfo().Telegram; v.Running || !strings.Contains(v.Error, "занят") || !v.Enabled {
		t.Fatalf("%+v", v)
	}
	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: 80}); err == nil {
		t.Fatal("port 80")
	}
	// The default port is kept as 0.
	c.SaveTelegram(TelegramInput{Enabled: false, Port: zapret.DefaultTelegramPort})
	if cfg, _ := c.Store.LoadZapret(); cfg.Telegram.Port != 0 || cfg.Telegram.TelegramPort() != 1443 {
		t.Fatalf("%+v", cfg.Telegram)
	}
	// Not connected: the VPN fallback says so (the bridge then goes direct).
	if _, err := c.tgVPNDial(t.Context(), tgwsTestDC()); err == nil || !strings.Contains(err.Error(), "не подключён") {
		t.Fatalf("%v", err)
	}
}

func tgwsTestDC() netip.AddrPort { return netip.MustParseAddrPort("149.154.167.51:443") }

// noTelegramNet keeps the bridge off the network in tests: no WebSocket
// routes, no pool, no self-checks.
func noTelegramNet(t *testing.T) {
	t.Helper()
	cfg, first := tgBridgeConfig, tgCheckFirst
	t.Cleanup(func() { tgBridgeConfig, tgCheckFirst = cfg, first })
	tgCheckFirst = time.Hour
	tgBridgeConfig = func(c *Controller) tgws.Config {
		return tgws.Config{Log: c.Log, PoolSize: -1, Redirect: map[int]netip.Addr{},
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("no network in tests")
			}}
	}
}

// With HyRoute connected Telegram needs no proxy: the rule «Обход DPI:
// Telegram» takes its addresses to the bridge (the main server when the
// bridge is off), and the session gets the bridge as that rule's route.
func TestTelegramIntercepted(t *testing.T) {
	c, _ := newCtl(t)
	noTelegramNet(t)
	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: freePort(t)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.SaveTelegram(TelegramInput{}) })
	rs := c.Settings().Rules
	if len(rs) == 0 || rs[0].Name != "Обход DPI: Telegram" || rs[0].Profile != tgws.ProfileID || !slices.Equal(rs[0].Fallback, []string{""}) ||
		rs[0].Protocol != "tcp" || !slices.Contains(rs[0].Domains, "149.154.160.0/20") || rs[0].Action != rules.Tunnel {
		t.Fatalf("%+v", rs)
	}
	for _, w := range c.RuleWarnings() {
		if w.Profile == tgws.ProfileID {
			t.Fatalf("%+v", w)
		}
	}
	if n := c.profileName(tgws.ProfileID); n != "Telegram через WebSocket" {
		t.Fatal(n)
	}
	ex := c.Explain(ExplainQuery{Target: "149.154.167.51", Proto: "tcp", Port: 443}, nil)
	if ex.Winner.Name != "Обход DPI: Telegram" {
		t.Fatalf("%+v", ex.Winner)
	}
	var cfg session.Config
	c.tgSession(&cfg)
	tun := cfg.Extra[tgws.ProfileID]
	if tun == nil || !tun.Available() {
		t.Fatal("no route to the bridge")
	}
	// A connection through it: the bridge passes it on (no network here:
	// it fails, and says so).
	conn, err := tun.Dial(t.Context(), socks5.AddrFromAddrPort(netip.MustParseAddrPort("149.154.167.51:443")))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(make([]byte, 64))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("answered with no network")
	}
	conn.Close()
	if v := c.ZapretInfo().Telegram; v.Stats.Failed != 1 || v.Intercepted {
		t.Fatalf("%+v", v)
	}
	// Off: the route goes, the rule too.
	if err := c.SaveTelegram(TelegramInput{}); err != nil {
		t.Fatal(err)
	}
	if tun.Available() {
		t.Fatal("still available")
	}
	for _, r := range c.Settings().Rules {
		if r.Name == "Обход DPI: Telegram" {
			t.Fatal("rule kept")
		}
	}
}

// Connected with «Telegram без VPN» on: the session gets the bridge as the
// rule's route and the main server for the rule's fallback, nothing else.
func TestTelegramConnect(t *testing.T) {
	c, started := newCtl(t)
	noTelegramNet(t)
	if _, err := c.ImportURIs("hysteria2://p1@a.example:443#NL"); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveTelegram(TelegramInput{Enabled: true, Port: freePort(t)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.SaveTelegram(TelegramInput{}) })
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	if f.cfg.Extra[tgws.ProfileID] == nil || !f.cfg.Extra[tgws.ProfileID].Available() {
		t.Fatalf("%+v", f.cfg.Extra)
	}
	if len(f.cfg.Profiles) != 1 || f.cfg.Profiles[0].Name != "NL" {
		t.Fatalf("%+v", f.cfg.Profiles)
	}
	if v := c.ZapretInfo().Telegram; !v.Intercepted {
		t.Fatalf("%+v", v)
	}
	r := f.cfg.Rules.EvaluateDomain(rules.Subject{Proto: 6, Dst: netip.MustParseAddrPort("149.154.167.51:443")}, "", rules.SrcNone)
	if r.Action != rules.Tunnel || r.Profile != tgws.ProfileID || len(r.Fallback) != 1 || r.Fallback[0] == "" {
		t.Fatalf("%+v", r)
	}
	c.Disconnect()
}
