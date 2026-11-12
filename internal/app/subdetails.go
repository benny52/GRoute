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
	// These converter errors are constant strings with no imported values.
	switch msg {
	case "поддерживается только Hysteria версии 2", "нужен транспорт hysteria с TLS",
		"невозможно перенести pinnedPeerCertSha256 в Hysteria 2", "невозможно перенести проверку сертификата TLS в Hysteria 2",
		"некорректная маска salamander для Hysteria 2",
		"настройка packetSize маски salamander не переносится", "несколько масок udphop не поддерживаются",
		"неподдерживаемая UDP-маска Hysteria 2", "некорректный диапазон портов Hysteria 2",
		"неподдерживаемый интервал смены порта Hysteria 2", "неподдерживаемая цепочка прокси Hysteria 2",
		"неподдерживаемый режим смены порта Hysteria 2", "некорректные параметры смены порта Hysteria 2",
		"неподдерживаемая конфигурация смены адреса или порта Hysteria 2":
		return msg
	}
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

// 3x-ui encodes a client .conf directly in vpn://. The same sections
// appear in WireGuard: require an AWG-specific option in [Interface].
func isAWGConfig(config string) bool {
	section := ""
	var private, peer, obfuscated bool
	for line := range strings.SplitSeq(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch section {
		case "[interface]":
			switch key {
			case "privatekey":
				private = true
			case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5":
				obfuscated = true
			}
		case "[peer]":
			if key == "publickey" {
				peer = true
			}
		}
	}
	return private && peer && obfuscated
}

// Other Amnezia clients encode a JSON container, sometimes Qt-compressed.
func amneziaWG(link string, budget *int) bool {
	_, payload, _ := strings.Cut(link, "://")
	payload, _, _ = strings.Cut(payload, "#")
	const maxConfig = 256 << 10
	if len(payload) > maxConfig*2 || len(payload) > *budget {
		return false
	}
	*budget -= len(payload)
	raw, ok := decodeBase64(payload)
	if !ok || len(raw) < 4 || len(raw) > maxConfig {
		return false
	}
	data := []byte(raw)
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		return isAWGConfig(raw)
	}
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
	r := SubReport{Skipped: l.Skipped}
	seen := map[string]bool{}
	labels := map[string]string{}
	for _, p := range l.Profiles {
		entry := profileEntry(p)
		labels[p.Name] = entry.Name + " (" + entry.Protocol + ")"
		key := connKey(p)
		if seen[key] {
			r.Duplicates = append(r.Duplicates, entry)
			continue
		}
		r.Profiles = append(r.Profiles, entry)
		seen[key] = true
	}
	r.Warnings = safeWarnings(l.Warnings, labels)
	return r
}

// A parser warning may quote a URL parameter, a path or a value from the
// panel. Classify its message separately from its profile name, returning
// only allowlisted field names to the UI.
func safeWarnings(warnings []string, labels map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range warnings {
		var note string
		switch {
		case strings.HasPrefix(w, "сообщение панели: «"):
			note = "Панель передала информационную запись."
		case strings.HasPrefix(w, "в подписке ") && strings.HasSuffix(w, fmt.Sprintf(": взяты первые %d", maxSubServers)):
			note = fmt.Sprintf("Достигнут лимит в %d серверов.", maxSubServers)
		default:
			// Labels can themselves contain ": ". The message begins after
			// the longest matching known profile name. Bound candidate work
			// on untrusted panel strings; longer names just lose the label.
			var label string
			_, msg, _ := strings.Cut(w, ": ")
			for i := range min(len(w), 512) {
				if w[i] == ':' && strings.HasPrefix(w[i:], ": ") {
					if display, ok := labels[w[:i]]; ok {
						label, msg = display, w[i+2:]
					}
				}
			}
			note = parameterWarning(msg)
			if label != "" {
				note = label + " — " + note
			}
		}
		if !seen[note] {
			out = append(out, note)
			seen[note] = true
		}
	}
	return out
}

func parameterWarning(msg string) string {
	switch {
	case msg == "Hysteria 2: используются штатные параметры QUIC клиента вместо quicParams Xray":
		return msg
	case strings.HasPrefix(msg, "obfs-password without obfs:"):
		return "Для пароля обфускации без типа выбран salamander."
	case strings.HasPrefix(msg, "allowInsecure:"), strings.HasPrefix(msg, "insecure:"), strings.HasPrefix(msg, "skip-cert-verify:"):
		return "Xray продолжает проверять сертификат сервера."
	case strings.HasPrefix(msg, "pinSHA256 "):
		return "Проверьте отпечаток SHA-256 сертификата."
	case strings.HasPrefix(msg, "xhttp extra: «"), strings.HasPrefix(msg, "xhttp: «"):
		_, rest, _ := strings.Cut(msg, "«")
		field, _, _ := strings.Cut(rest, "»")
		switch field {
		case "downloadSettings.tlsSettings.masterKeyLog", "downloadSettings.tlsSettings.certificates", "downloadSettings.sockopt", "downloadSettings.tlsSettings.allowInsecure":
			return "XHTTP: поле " + field + " исключено из настроек клиента."
		}
		return "XHTTP: расширенные настройки содержат поле, которое клиент не принимает."
	case strings.HasPrefix(msg, "xhttp conflict: "):
		field := strings.TrimPrefix(msg, "xhttp conflict: ")
		switch field {
		case "mode":
			return "XHTTP: для mode использовано значение из строки ссылки."
		case "sessionIDPlacement", "sessionIDKey", "xPaddingBytes":
			return "XHTTP: значения расходятся. Использовано поле " + field + " из extra."
		}
	case strings.HasPrefix(msg, "fm:"):
		return "Часть настроек маскировки fm не перенесена."
	}
	if msg == "ignored parameter ech: not an inline ECH config list" {
		return "ECH пропущен: в ссылке должен быть встроенный список конфигурации."
	}
	field, fromQuery := strings.CutPrefix(msg, "ignored parameter ")
	if !fromQuery {
		field, _, _ = strings.Cut(strings.TrimPrefix(msg, "ignored "), " ")
	}
	switch field {
	case "up", "down", "ech", "mportHopInt", "ports", "sockopt", "finalmask", "mux", "x_padding_bytes", "support-x25519mlkem768":
		return "Параметр " + field + " не применён."
	}
	return "В профиле есть неподдерживаемый дополнительный параметр."
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
	labels := map[string]string{}
	for _, p := range c.profiles.List {
		if p.Source == "sub:"+id && !p.Missing {
			entry := profileEntry(p)
			saved = append(saved, entry)
			labels[p.Name] = entry.Name + " (" + entry.Protocol + ")"
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
	r := SubReport{Profiles: saved, Partial: true, Warnings: safeWarnings(s.Warnings, labels)}
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
