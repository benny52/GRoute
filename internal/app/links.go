package app

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
)

// Links is the result of parsing pasted text or a subscription body.
type Links struct {
	Profiles []hysteria.Profile
	Warnings []string
	Errors   []string
	// Ignored counts share links of other protocols (vmess://, ss://,
	// trojan://, tuic://, hysteria:// v1 …) by scheme.
	Ignored map[string]int
	// Base64: the text was a base64-encoded link list.
	Base64 bool
	// Format: the text was a client config (subfmt), "" for links.
	Format string
	// Notices are the texts of placeholder servers (panelNotice): what
	// the panel says instead of, or next to, the servers.
	Notices []string
	Skipped []SubEntry
}

func (l *Links) IgnoredTotal() int {
	n := 0
	for _, v := range l.Ignored {
		n += v
	}
	return n
}

// ParseLinks accepts a client .conf or a plain/base64 subscription with
// Hysteria 2, VLESS and AmneziaWG share links.
func ParseLinks(text string) Links {
	res := Links{Ignored: map[string]int{}, Warnings: []string{}, Errors: []string{}}
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	if looksLikeAWGConfig(text) {
		p, err := hysteria.ParseAWGConfig(text)
		res.Format = "AmneziaWG .conf"
		if err != nil {
			res.Errors = []string{err.Error()}
			res.Skipped = []SubEntry{skippedEntry("", "amneziawg", err.Error())}
		} else {
			res.Profiles = []hysteria.Profile{p}
		}
		return res
	}
	if !strings.Contains(text, "://") {
		if dec, ok := decodeBase64(text); ok && strings.Contains(dec, "://") {
			text, res.Base64 = dec, true
		}
	}
	n := 0
	decodeBudget := maxSubBody
	for _, f := range splitLinks(text) {
		scheme, _, _ := strings.Cut(f, "://")
		scheme = strings.ToLower(scheme)
		if scheme == "http" || scheme == "https" {
			continue // a web address in a text, not a share link
		}
		if !slices.Contains(hysteria.LinkSchemes, scheme) {
			res.Ignored[scheme]++
			res.Skipped = append(res.Skipped, skippedLink(f, scheme, ""))
			continue
		}
		if scheme != "vpn" && scheme != "amneziawg" {
			if msg, ok := panelNotice(f); ok {
				res.Notices = append(res.Notices, msg)
				continue
			}
		}
		n++
		p, warns, err := hysteria.ParseURI(f)
		label := p.Name
		if label == "" {
			label = p.Host
		}
		if err != nil {
			if scheme == "vpn" {
				entry := skippedLink(f, scheme, "")
				if amneziaWG(f, &decodeBudget) {
					entry.Protocol = "AmneziaWG"
					entry.Reason = "Неполная или неподдерживаемая конфигурация AmneziaWG"
					res.Errors = append(res.Errors, fmt.Sprintf("ссылка %d: %s", n, entry.Reason))
				} else {
					res.Ignored[scheme]++
				}
				res.Skipped = append(res.Skipped, entry)
				continue
			}
			res.Errors = append(res.Errors, fmt.Sprintf("ссылка %d: %v", n, err))
			res.Skipped = append(res.Skipped, skippedLink(f, scheme, err.Error()))
			continue
		}
		for _, w := range warns {
			res.Warnings = append(res.Warnings, label+": "+w)
		}
		if p.Name == "" {
			p.Name = p.Host
		}
		res.Profiles = append(res.Profiles, p)
	}
	for _, m := range res.Notices {
		res.Warnings = append(res.Warnings, "сообщение панели: «"+m+"»")
	}
	return res
}

// panelNotice reports a placeholder server: a link to 0.0.0.0 or ::
// (or to port 1 of the loopback) is no server, but a panel's message in
// its name, as Remnawave and Marzban send «Приложение не поддерживается»,
// «Подписка истекла» or the days left.
func panelNotice(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil || !(a.IsUnspecified() || a.IsLoopback() && u.Port() == "1") {
		return "", false
	}
	msg := strings.TrimSpace(u.Fragment)
	if msg == "" {
		msg = "без текста"
	}
	return msg, true
}

// linkStart finds "scheme://" at the start of a line or after whitespace
// or a byte order mark (a base64 list may encode one, and so may each
// file of lists joined together).
var linkStart = regexp.MustCompile(`(?:^|[\s\x{FEFF}])([A-Za-z][A-Za-z0-9+.\-]*://)`)

// splitLinks returns the share links in text. A link runs to the end of
// its line or to the next link on the same line, so names (the #fragment)
// may contain spaces: "hy2://…#🇳🇱 Нидерланды напрямую".
func splitLinks(text string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		idx := linkStart.FindAllStringSubmatchIndex(line, -1)
		for i, m := range idx {
			end := len(line)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			if l := strings.TrimSpace(line[m[2]:end]); l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// decodeBase64 accepts standard and URL alphabets, with or without
// padding, and ignores line breaks.
func decodeBase64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// Only interpret a complete file, never an embedded sample in a subscription.
func looksLikeAWGConfig(text string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.EqualFold(line, "[Interface]")
	}
	return false
}
