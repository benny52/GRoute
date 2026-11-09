# Telegram без VPN (internal/tgws)

A Go port of [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT):
Telegram Desktop's MTProto goes to Telegram through the WebSocket
endpoints of its web version, which a DPI that blocks the data centers'
addresses tends to let through.

## The chain

```
Telegram Desktop ─MTProto proxy, secret─▶ 127.0.0.1:1443 (tgws.Proxy)
   ─▶ tgws.Bridge ─▶ wss://kwsN[-1].web.telegram.org/apiws  at 149.154.167.220
                  ─▶ (no WebSocket) Cloudflare, when the DPI bypass carries it
                  ─▶ the main VPN server, TCP to the data center
                  ─▶ Cloudflare, when it was not tried before the VPN
                  ─▶ TCP to the data center, direct
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
  an hour). Cloudflare (below) comes before the VPN or after it.
- **Cloudflare** (`cloudflare.go`, tg-ws-proxy's CF proxy and CF Worker).
  The user's Workers first: `wss://<worker>/apiws?dst=<data center>&dc=N`,
  the Worker opens TCP there and carries raw bytes. Then tg-ws-proxy's
  domains: `wss://kwsN.<domain>/apiws`, Cloudflare carries the upgrade to
  the data center (one message per packet, as Telegram's own). The domain
  that worked last for a data center first, the rest shuffled, two tried
  per connection (6 s each), one that failed skipped for 5 minutes. The
  list is fetched from tg-ws-proxy's repository on start and hourly (kept
  encoded there and in `cloudflareEncoded`: a public list read in plain
  text is blocked; the built-in copy is used until a fetch works). Some
  providers cut Cloudflare's addresses after a few kilobytes (a check of a
  few hundred bytes passes anyway), so Cloudflare goes before the VPN only
  when winws2 carries its hosts: the app adds them to Discord's list (its
  methods are picked against Cloudflare: Discord's media live there), else
  to the own sites' list, when the bypass runs for that target
  (`cloudflareListsLocked`, `zapret.WriteLists`' extra). Otherwise it comes
  after the VPN, in place of direct TCP. Cloudflare and the domain's owner
  see that someone uses Telegram, from where and when, never the messages.
- **Media** (`media.go`). On some accounts (without Premium, tg-ws-proxy's
  notes say) a data center's media connections over `/apiws` get no
  answer. After 3 media connections in a row to one data center whose
  client sent a request and got not a byte back, that data center's media
  skip WebSocket for an hour (the stats say which).
- **The pool** (`pool.go`). Two WebSocket connections per data center and
  media kind open ahead (`Warm`), each used once, dropped after 60 s idle;
  a refill that fails backs off up to an hour.

## Without a proxy set (the engine)

With HyRoute connected the rule «Обход DPI: Telegram» (Telegram's
networks, `tgws.Networks`; TCP 80, 443, 5222; `Tunnel` through
`tgws.ProfileID`, fallback the main target) sends Telegram's connections
to the bridge: `session.Config.Extra` serves that profile ID in-process
(`tgws.Tunnel`: the relay's dial returns one end of a `net.Pipe`, the
bridge's `ServeTransparent` the other). It reads the first 64 bytes: an
obfuscated init with no secret for a data center with a WebSocket route
goes over it (re-keyed as from the proxy), else over Cloudflare when that
goes before the VPN; anything else (web.telegram.org's TLS, the HTTP
transport), and what no such route opened, is passed on unchanged to the
address it was going to, through the main server's SOCKS5, else over
Cloudflare (an MTProto init, re-keyed), else directly (`passOn`). While the bridge is off the rule's fallback (the main server)
takes it. The route is TCP only: calls and other UDP go by the other
rules.

## Self-checks (health.go)

`Bridge.Check` asks for `req_pq_multi` over WebSocket (DC2, then DC4) and
checks the `resPQ`. A failure sets `wsDown`: connections skip WebSocket
(no wait for a dead route each time) until a check finds it answering;
the check then also says which fallback answers (VPN, direct). When a
Cloudflare route is set up the check asks through it too, every time; a
failure sets `cfDown` the same way. The app
runs it 5 s after the bridge starts and every 5 minutes (`tgChecks`); the
page shows the result.

## In the app

`zapret.Settings.Telegram` (zapret.json): on, the port (0 = 1443), the
secret (HyRoute makes one; it stays, as Telegram keeps the proxy it
added), `noCloudflare`, the user's `workers` (hosts, at most 5). The
Cloudflare list is fetched through `directTransport` (`tgFetchCloudflare`);
a new list re-applies the bypass (the bridge's domains, winws2's lists). `Controller.tgApplyLocked` runs with every apply of the bypass and
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
backed off), the pool. `cloudflare_test.go`: the list's decoding, a dead
domain skipped, Cloudflare before or after the VPN, a Worker told the data
center, the engine's path, media that get no answer, the self-check.
`live_test.go` (CI, `HYROUTE_TGWS_LIVE=1`) asks real Telegram for
`req_pq_multi` through each route, tg-ws-proxy's Cloudflare domains
included, and checks the `resPQ` (the domains are not logged).
