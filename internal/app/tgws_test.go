package app

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

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
	old := tgListenAddr
	t.Cleanup(func() { tgListenAddr = old })
	tgListenAddr = func(p int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(p)) }

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
