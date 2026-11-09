package tgws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Cloudflare routes, for when Telegram's own WebSocket address does not
// open, and for the data centers it has no WebSocket for (tg-ws-proxy's
// CF proxy and CF Worker):
//
//   - a domain proxied by Cloudflare whose kwsN names point at the data
//     centers: Cloudflare takes the WebSocket upgrade and carries it to
//     the data center (kwsN.<domain>/apiws). tg-ws-proxy's author keeps a
//     list of such domains; the bridge takes it from their repository and
//     keeps a built-in copy.
//   - a Cloudflare Worker of the user's own: it opens TCP to the data
//     center named in the URL and carries the WebSocket's bytes.
//
// Either way Cloudflare and the domain's owner see that someone uses
// Telegram, from which address and when, never the messages: MTProto is
// encrypted end to end with the account's key.

// CloudflareListURL is tg-ws-proxy's list of its Cloudflare domains (one
// per line, encoded as cloudflareEncoded).
const CloudflareListURL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

// cloudflareEncoded is tg-ws-proxy's built-in list (proxy/config.py),
// kept encoded as there: the domains of a public list are blocked once
// they are read in plain text.
var cloudflareEncoded = []string{
	"virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
	"awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
	"vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
	"orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
}

// minCloudflare: a fetched list with fewer valid domains is not taken.
const minCloudflare = 3

// decodeDomain undoes tg-ws-proxy's encoding (_dd): the letters before
// ".com" are shifted back by their count and the suffix is ".co.uk"; a
// name without ".com" is taken as it is.
func decodeDomain(s string) string {
	p, ok := strings.CutSuffix(s, ".com")
	if !ok {
		return s
	}
	n := 0
	for _, c := range p {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	var b strings.Builder
	for _, c := range p {
		switch {
		case c >= 'a' && c <= 'z':
			c = 'a' + ((c-'a'-rune(n))%26+26)%26
		case c >= 'A' && c <= 'Z':
			c = 'A' + ((c-'A'-rune(n))%26+26)%26
		}
		b.WriteRune(c)
	}
	return b.String() + ".co.uk"
}

// DefaultCloudflare is the built-in list of Cloudflare domains.
func DefaultCloudflare() []string { return ParseCloudflare(strings.Join(cloudflareEncoded, "\n")) }

// ParseCloudflare reads a list as CloudflareListURL serves it: decoded,
// valid names only, each once.
func ParseCloudflare(text string) []string {
	var out []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := strings.ToLower(decodeDomain(line))
		if !ValidHost(d) || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// FetchCloudflare takes the current list from tg-ws-proxy's repository
// through client; an error when it holds fewer than minCloudflare valid
// domains (the built-in list stays).
func FetchCloudflare(ctx context.Context, client *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CloudflareListURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HyRoute")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("список доменов Cloudflare: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	list := ParseCloudflare(string(body))
	if len(list) < minCloudflare {
		return nil, fmt.Errorf("список доменов Cloudflare: %d годных", len(list))
	}
	return list, nil
}

// ValidHost reports a DNS name of two or more labels (a Worker's host,
// a domain of the list).
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	return len(tld) >= 2 && strings.IndexFunc(tld, func(c rune) bool { return c < '0' || c > '9' }) >= 0
}

// cfBackoff: a domain or Worker that did not open is skipped this long.
var cfBackoff = 5 * time.Minute

// cfTries: domains tried per connection (each up to cfTimeout), so a
// connection does not wait on a whole list of dead ones.
const (
	cfTries   = 2
	cfTimeout = 6 * time.Second
)

// SetCloudflare replaces the Cloudflare domains (nil: none) and says
// whether that route goes before the VPN: only when the DPI bypass covers
// Cloudflare's addresses (in Russia some providers cut connections to
// them after a few kilobytes; the VPN has no such trouble).
func (b *Bridge) SetCloudflare(domains []string, beforeVPN bool) {
	d := append([]string(nil), domains...)
	b.cf.Store(&d)
	b.cfFirst.Store(beforeVPN)
}

// cloudflare returns the domains in use.
func (b *Bridge) cloudflare() []string {
	if p := b.cf.Load(); p != nil {
		return *p
	}
	return nil
}

// cloudflareOn: a Cloudflare route is set up.
func (b *Bridge) cloudflareOn() bool { return len(b.cfg.Workers) > 0 || len(b.cloudflare()) > 0 }

// cfUsable: a Cloudflare route is set up for h and self-checks do not
// rule it out.
func (b *Bridge) cfUsable(h Hello) bool { return !h.Test && b.cloudflareOn() && !b.cfDown.Load() }

// skipping reports a domain or Worker in its backoff.
func (b *Bridge) skipping(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Before(b.cfAfter[name])
}

func (b *Bridge) cfResult(name string, dc int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.cfAfter[name] = time.Now().Add(cfBackoff)
		return
	}
	delete(b.cfAfter, name)
	if dc != 0 {
		b.cfPick[dc] = name
	}
}

// connectCloudflare opens a WebSocket to data center dc through the
// user's Workers, else the Cloudflare domains (the one that worked last
// for dc first). frames: the connection takes one message per packet
// (Telegram's /apiws behind Cloudflare); a Worker carries raw bytes.
func (b *Bridge) connectCloudflare(ctx context.Context, dc int) (w *wsConn, route string, frames bool, err error) {
	var errs []error
	dst, ok := directAddr(dc, false)
	if ok {
		q := url.Values{"dst": {dst.Addr().String()}, "dc": {strconv.Itoa(dc)}}
		for _, host := range b.cfg.Workers {
			if b.skipping(host) {
				continue
			}
			t := wsTarget{Addr: net.JoinHostPort(host, "443"), Host: host, Path: "/apiws?" + q.Encode(), Roots: b.cfg.Roots}
			cctx, cancel := context.WithTimeout(ctx, cfTimeout)
			w, err := dialWS(cctx, b.cfg.Dial, t)
			cancel()
			b.cfResult(host, 0, err)
			if err == nil {
				return w, RouteWorker, false, nil
			}
			errs = append(errs, fmt.Errorf("Worker: %w", err))
			if ctx.Err() != nil {
				return nil, "", false, errors.Join(errs...)
			}
		}
	}
	tries := 0
	for _, d := range b.cfOrder(dc) {
		if tries == cfTries || ctx.Err() != nil {
			break
		}
		if b.skipping(d) {
			continue
		}
		tries++
		host := fmt.Sprintf("kws%d.%s", dc, d)
		t := wsTarget{Addr: net.JoinHostPort(host, "443"), Host: host, Path: "/apiws", Roots: b.cfg.Roots}
		cctx, cancel := context.WithTimeout(ctx, cfTimeout)
		w, err := dialWS(cctx, b.cfg.Dial, t)
		cancel()
		b.cfResult(d, dc, err)
		if err == nil {
			return w, RouteCF, true, nil
		}
		errs = append(errs, fmt.Errorf("Cloudflare: %w", err))
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("Cloudflare: все домены недавно не отвечали"))
	}
	return nil, "", false, errors.Join(errs...)
}

// cfOrder: the domain that worked last for dc, then the rest shuffled
// (connections spread over the domains, as tg-ws-proxy's balancer does).
func (b *Bridge) cfOrder(dc int) []string {
	list := append([]string(nil), b.cloudflare()...)
	rand.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	b.mu.Lock()
	pick := b.cfPick[dc]
	b.mu.Unlock()
	for i, d := range list {
		if d == pick {
			list[0], list[i] = list[i], list[0]
			break
		}
	}
	return list
}
