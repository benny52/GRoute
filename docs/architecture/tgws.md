# Telegram без VPN (internal/tgws)

A Go port of [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT):
Telegram Desktop's MTProto goes to Telegram through the WebSocket
endpoints of its web version, which a DPI that blocks the data centers'
addresses tends to let through.

## The chain

```
Telegram Desktop ─MTProto proxy, secret─▶ 127.0.0.1:1443 (tgws.Proxy)
   ─▶ tgws.Bridge ─▶ wss://kwsN[-1].web.telegram.org/apiws  at 149.154.167.220
                  ─▶ (no WebSocket) the main VPN server, TCP to the data center
                  ─▶ (no VPN) TCP to the data center, direct
```

- **The init** (`obfs.go`). A client's 64-byte obfuscated init carries a key
  and an IV (with the proxy secret: `sha256(key‖secret)`), and, encrypted,
  the transport's tag (abridged, intermediate, padded intermediate) and the
  data center (negative: media, +10000: test). `ReadHello` reads it; a
  wrong secret gives no known tag. The bridge makes a new init for
  Telegram's side (`relayInit`, no secret) and re-keys the stream both
  ways: Telegram sees an ordinary obfuscated connection, the content stays
  MTProto-encrypted end to end.
- **WebSocket** (`ws.go`). TLS to the redirect address with SNI and Host
  `kwsN.web.telegram.org`, `Sec-WebSocket-Protocol: binary`, path `/apiws`
  (`/apiws_test` for the test data centers). Each transport packet goes as
  a message of its own, as the web version sends them (`split.go` reads the
  lengths from the plain bytes). Media first tries `kwsN-1`.
- **Fronting.** When the name is cut, the same server is asked with
  `FrontingSNI` in TLS and the right Host: unlike tg-ws-proxy, the
  certificate is still verified, against `kwsN.web.telegram.org`
  (`VerifyConnection`). The way that worked last is tried first.
- **Routes** (`bridge.go`). Telegram serves WebSocket for data centers 2 and
  4 at 149.154.167.220 (`DefaultRedirect`); the others, and a refused
  upgrade (302), take the main VPN server through its SOCKS5
  (`Controller.tgVPNDial`; a group: its current member) when HyRoute is
  connected, then direct TCP with a backoff per address (30 s, doubling to
  an hour). tg-ws-proxy's Cloudflare domains (third parties' relays) are
  not used.
- **The pool** (`pool.go`). Two WebSocket connections per data center and
  media kind open ahead (`Warm`), each used once, dropped after 60 s idle;
  a refill that fails backs off up to an hour.

## In the app

`zapret.Settings.Telegram` (zapret.json): on, the port (0 = 1443), the
secret (HyRoute makes one; it stays, as Telegram keeps the proxy it
added). `Controller.tgApplyLocked` runs with every apply of the bypass and
on start, on both systems (winws2 itself is Windows-only). The page
opens the `tg://proxy` link (`OpenTelegramProxy`: through Explorer on
Windows, the elevated process never starts a program of the user's) or
copies it; the link, with its secret, is never shown.

## Tests

`internal/tgws/tgws_test.go`: a client as Telegram does it (with a secret,
every transport) against a fake Telegram over TLS and plain TCP that
checks the relay init, that each WebSocket message is one packet, and
echoes: the WebSocket route, fronting (and a certificate for another name
refused), 302 → VPN → direct TCP, nothing reachable (closed, counted,
backed off), the pool. `live_test.go` (CI, `HYROUTE_TGWS_LIVE=1`) asks real
Telegram for `req_pq_multi` through each route and checks the `resPQ`.
