package tgws

import "time"

// Media over Telegram's WebSocket: on some accounts (without Premium, as
// tg-ws-proxy's notes say) a data center's media connections over /apiws
// open and then get no answer, so photos and videos never load; the
// advice there is to take that data center off WebSocket. The bridge does
// it by itself: after mediaStrikes media connections in a row to one data
// center that Telegram never answered (the client sent a request, not a
// byte came back), its media go by the other routes for mediaPause.

var (
	mediaStrikes = 3
	mediaPause   = time.Hour
)

// wsUsable: h goes over Telegram's WebSocket.
func (b *Bridge) wsUsable(h Hello) bool {
	if _, ok := b.cfg.Redirect[h.DC]; !ok || b.wsDown.Load() {
		return false
	}
	if !h.Media {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !time.Now().Before(b.mediaOff[h.DC])
}

// mediaResult learns from a connection over WebSocket that ended: sent
// and got are the bytes past the init each way.
func (b *Bridge) mediaResult(h Hello, sent, got int64) {
	if !h.Media || sent == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if got > 0 {
		delete(b.mediaFails, h.DC)
		return
	}
	b.mediaFails[h.DC]++
	if b.mediaFails[h.DC] >= mediaStrikes {
		delete(b.mediaFails, h.DC)
		b.mediaOff[h.DC] = time.Now().Add(mediaPause)
		b.cfg.Log.Warn("tgws: media over WebSocket get no answer, other routes for a while", "dc", h.DC)
	}
}
