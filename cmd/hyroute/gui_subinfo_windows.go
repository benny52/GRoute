//go:build windows

package main

import "errors"

// OpenTelegramProxy opens the tg://proxy link of «Telegram без VPN»:
// Telegram, through the running Explorer (unelevated), adds the proxy.
func (g *GUI) OpenTelegramProxy() error {
	u := g.ctl.TelegramLink()
	if u == "" {
		return errors.New("прокси для Telegram не запущен")
	}
	if err := shellExecuteInExplorer(u); err != nil {
		g.ctl.Log.Warn("cannot open the Telegram proxy link through Explorer", "err", err)
		return errors.New("не удалось открыть Telegram. Скопируйте ссылку и откройте её в Telegram")
	}
	return nil
}

// OpenSubscriptionSupport opens the support link the panel of subscription
// id sent, in the user's browser through the running Explorer (unelevated).
// The page names the subscription, never passes a URL, and there is no
// fallback to starting a browser from this elevated process: the link is on
// screen with «Скопировать» (CopyText) instead.
func (g *GUI) OpenSubscriptionSupport(id string) error {
	u, err := g.ctl.SupportLink(id)
	if err != nil {
		return err
	}
	if err := shellExecuteInExplorer(u); err != nil {
		g.ctl.Log.Warn("cannot open a support link through Explorer", "err", err)
		return errors.New("не удалось открыть ссылку в браузере. Скопируйте её")
	}
	return nil
}
