package app

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/store"
)

// SubEntry is display data. Never send a share link or parsed settings to the report.
type SubEntry struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason,omitempty"`
	Count    int    `json:"count,omitempty"` // grouped totals when an old snapshot is missing
}

type SubReport struct {
	Profiles   []SubEntry `json:"profiles"`
	Skipped    []SubEntry `json:"skipped"`
	Duplicates []SubEntry `json:"duplicates"`
	Warnings   []string   `json:"warnings"`
	Partial    bool       `json:"partial,omitempty"`
}

func displayName(name string, secrets ...string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "://") || strings.ContainsAny(name, "@=?") || strings.ContainsFunc(name, unicode.IsControl) {
		return "Без имени"
	}
	for _, secret := range secrets {
		if secret != "" && (name == secret || len(secret) >= 4 && strings.Contains(name, secret)) {
			return "Без имени"
		}
	}
	return string([]rune(name)[:min(120, len([]rune(name)))])
}

var schemeLabel = regexp.MustCompile(`^[a-z][a-z0-9+.\-]{0,23}$`)

func protocolLabel(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "hy2", "hysteria2":
		return "Hysteria 2"
	case "vless":
		return "VLESS"
	}
	if !schemeLabel.MatchString(s) {
		return "Неизвестный"
	}
	return s
}

func skippedEntry(name, scheme, parserError string) SubEntry {
	entry := SubEntry{Name: displayName(name), Protocol: protocolLabel(scheme), Reason: "Протокол не поддерживается"}
	if parserError != "" {
		entry.Reason = invalidReason(parserError)
	} else if scheme == "vpn" {
		entry.Reason = "Тип VPN-конфигурации не определён"
	}
	return entry
}

func skippedLink(link, scheme, cause string) SubEntry {
	source, fragment, _ := strings.Cut(link, "#")
	name, _ := url.PathUnescape(fragment)
	// Never use userinfo, the authority or the opaque payload as a display name.
	if name != "" && strings.Contains(source, name) {
		name = ""
	}
	return skippedEntry(name, scheme, cause)
}

// Parser errors can quote an invalid port, malformed host or other untrusted
// field. Return a reason we own instead of exposing any part of that value.
func invalidReason(msg string) string {
	msg = strings.ToLower(msg)
	for _, rule := range []struct{ token, reason string }{
		{"uuid", "Некорректный идентификатор пользователя"}, {"id пользователя", "Некорректный идентификатор пользователя"},
		{"obfs", "Некорректные параметры обфускации"}, {"port", "Некорректный порт сервера"}, {"порт", "Некорректный адрес или порт сервера"},
		{"host", "Некорректный адрес сервера"}, {"адрес", "Некорректный адрес сервера"}, {"auth", "Некорректные данные авторизации"},
		{"transport", "Неподдерживаемый транспорт"}, {"транспорт", "Неподдерживаемый транспорт"},
		{"reality", "Некорректные параметры REALITY"}, {"security", "Неподдерживаемые настройки защиты"},
		{"flow", "Неподдерживаемое значение flow"}, {"encryption", "Неподдерживаемое шифрование"}, {"json", "Некорректная структура JSON"},
	} {
		if strings.Contains(msg, rule.token) {
			return rule.reason
		}
	}
	return "Некорректные параметры сервера"
}

// An Amnezia vpn link can contain different protocols. Identify AWG only
// from an explicit container in its JSON (plain or Qt qCompress framing).
func amneziaWG(link string, budget *int) bool {
	_, payload, _ := strings.Cut(link, "://")
	payload, _, _ = strings.Cut(payload, "#")
	const maxConfig = 256 << 10
	if len(payload) > maxConfig*2 || len(payload) > *budget {
		return false
	}
	*budget -= len(payload)
	raw, ok := decodeBase64(payload)
	if !ok || len(raw) < 4 {
		return false
	}
	data := []byte(raw)
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		n := binary.BigEndian.Uint32(data[:4])
		if n == 0 || n > maxConfig || int(n) > *budget {
			return false
		}
		*budget -= int(n)
		r, err := zlib.NewReader(bytes.NewReader(data[4:]))
		if err != nil {
			return false
		}
		defer r.Close()
		data, err = io.ReadAll(io.LimitReader(r, int64(n)+1))
		if err != nil || len(data) != int(n) {
			return false
		}
	}
	var cfg struct {
		DefaultContainer string `json:"defaultContainer"`
		Containers       []struct {
			Container string `json:"container"`
		} `json:"containers"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return false
	}
	if cfg.DefaultContainer != "" {
		return cfg.DefaultContainer == "amnezia-awg" || cfg.DefaultContainer == "amnezia-awg2"
	}
	return len(cfg.Containers) == 1 && (cfg.Containers[0].Container == "amnezia-awg" || cfg.Containers[0].Container == "amnezia-awg2")
}

func profileEntry(p hysteria.Profile) SubEntry {
	return SubEntry{Name: displayName(p.Name, p.Secrets()...), Protocol: p.ProtocolName()}
}

func importReport(l Links) SubReport {
	r := SubReport{Skipped: l.Skipped, Warnings: safeWarnings(l.Warnings)}
	seen := map[string]bool{}
	for _, p := range l.Profiles {
		key := connKey(p)
		if seen[key] {
			r.Duplicates = append(r.Duplicates, profileEntry(p))
			continue
		}
		r.Profiles = append(r.Profiles, profileEntry(p))
		seen[key] = true
	}
	return r
}

// Keep actionable parameter names from the parsers. Arbitrary parameter
// values, free-form panel notices and unknown query keys may contain secrets.
func safeWarnings(warnings []string) []string {
	var out []string
	for _, w := range warnings {
		const fallback = "Подписка содержит параметры, которые не удалось перенести."
		note := fallback
		switch {
		case strings.Contains(w, "сообщение панели"):
			note = "Панель передала информационную запись."
		case strings.Contains(w, "obfs-password without obfs"):
			note = "Для пароля обфускации без типа выбран salamander."
		case strings.Contains(w, "insecure") || strings.Contains(w, "провер"):
			note = "Xray продолжает проверять сертификат сервера."
		case strings.Contains(w, "pinSHA256"):
			note = "Проверьте отпечаток SHA-256 сертификата."
		case strings.Contains(w, "взяты первые"):
			note = fmt.Sprintf("Достигнут лимит в %d серверов.", maxSubServers)
		default:
			for _, parameter := range []string{"xhttp", "sockopt", "finalmask", "mux", "mportHopInt", "ports", "ech", "down", "up"} {
				if strings.Contains(w, parameter) {
					note = "Параметр " + parameter + " перенесён не полностью или пропущен."
					break
				}
			}
		}
		out = append(out, note)
	}
	return out
}

func (c *Controller) SubscriptionDetails(id string) (SubReport, error) {
	// Synchronize with manual/scheduled updates and rollbacks. Decrypt and
	// parse outside the controller mutex; the caller asks only on expansion.
	defer c.lockSub(id)()
	c.mu.Lock()
	i := slices.IndexFunc(c.subs, func(s store.Subscription) bool { return s.ID == id })
	if i < 0 {
		c.mu.Unlock()
		return SubReport{}, errors.New("подписка не найдена")
	}
	s := c.subs[i]
	var saved []SubEntry
	for _, p := range c.profiles.List {
		if p.Source == "sub:"+id && !p.Missing {
			saved = append(saved, profileEntry(p))
		}
	}
	c.mu.Unlock()

	if !s.SnapshotUnavailable {
		if body, err := c.Store.CurrentSnapshot(id); err == nil {
			if parsed, err := parseSubscription(body); err == nil {
				r := importReport(parsed)
				r.Profiles = saved
				return r, nil
			}
		}
	}
	r := SubReport{Profiles: saved, Partial: true, Warnings: safeWarnings(s.Warnings)}
	var schemes []string
	for scheme := range s.Ignored {
		schemes = append(schemes, scheme)
	}
	slices.Sort(schemes)
	for _, scheme := range schemes {
		entry := skippedEntry("", scheme, "")
		entry.Count = s.Ignored[scheme]
		r.Skipped = append(r.Skipped, entry)
	}
	if s.ErrorCount > 0 {
		r.Skipped = append(r.Skipped, SubEntry{Protocol: "Неизвестный", Count: s.ErrorCount, Reason: "Некорректные параметры сервера"})
	}
	return r, nil
}
