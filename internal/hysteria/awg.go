package hysteria

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AWGSettings keeps a canonical, comparable representation. The two option
// blocks contain only the allowed non-secret fields. Endpoint is in Host/Ports.
type AWGSettings struct {
	Interface string `json:"interface,omitempty"`
	Peer      string `json:"peer,omitempty"`
	AWGKeys
}

type AWGKeys struct {
	PrivateKey          string `json:"privateKey,omitempty"`
	PresharedKey        string `json:"presharedKey,omitempty"`
	HeaderProtectionKey string `json:"headerProtectionKey,omitempty"`
}

const maxAWGConfig = 256 << 10

var zeroAWGKey [32]byte

// Keep the order fixed so spelling/case/order in a file doesn't affect deduplication.
var awgInterfaceFields = strings.Fields("Address DNS MTU PrivateKey Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies")
var awgPeerFields = strings.Fields("PublicKey PresharedKey AllowedIPs Endpoint PersistentKeepalive")

func parseAWGURI(raw string) (Profile, error) {
	_, value, _ := strings.Cut(raw, "://")
	value, fragment, _ := strings.Cut(value, "#")
	if len(value) > base64.StdEncoding.EncodedLen(maxAWGConfig) {
		return Profile{}, errors.New("конфигурация AmneziaWG слишком велика")
	}
	var data []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		data, err = enc.DecodeString(value)
		if err == nil {
			break
		}
	}
	if err != nil {
		return Profile{}, errors.New("неверная кодировка конфигурации AmneziaWG")
	}
	p, err := ParseAWGConfig(string(data))
	if err == nil && fragment != "" {
		name, err := url.PathUnescape(fragment)
		if err != nil {
			return Profile{}, errors.New("неверное имя профиля AmneziaWG")
		}
		p.Name = p.awgName(name)
	}
	return p, err
}

func (p Profile) awgName(name string) string {
	if name == "" || strings.ContainsFunc(name, unicode.IsControl) || strings.Contains(name, "://") || len(name) > 512 {
		return p.Host
	}
	for _, key := range p.Secrets() {
		if key != "" && strings.Contains(name, key) {
			return p.Host
		}
	}
	return name
}

// ParseAWGConfig parses one 3x-ui client .conf. wg-quick's hooks and other
// system-level settings are intentionally outside a userspace client profile.
func ParseAWGConfig(config string) (Profile, error) {
	p := Profile{Protocol: ProtoAmneziaWG, PinServerIP: true}
	if len(config) > maxAWGConfig || !utf8.ValidString(config) {
		return Profile{}, errors.New("некорректный размер или кодировка AmneziaWG")
	}
	section, comment, name := "", "", ""
	fields := make(map[string]string)
	foundAWG := false
	for raw := range strings.SplitSeq(strings.TrimPrefix(config, "\ufeff"), "\n") {
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "#") {
			comment = strings.TrimSpace(raw[1:])
			continue
		}
		raw, _, _ = strings.Cut(raw, "#")
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			if section != "" {
				return Profile{}, errors.New("ожидается одна секция Interface")
			}
			section = "Interface"
			continue
		case "[peer]":
			if section != "Interface" {
				return Profile{}, errors.New("AmneziaWG поддерживает один Peer на сервер")
			}
			section = "Peer"
			name = comment
			continue
		}
		comment = ""
		key, value, ok := strings.Cut(line, "=")
		value = strings.TrimSpace(value)
		if !ok || value == "" || strings.ContainsFunc(value, unicode.IsControl) {
			return Profile{}, errors.New("неверная строка конфигурации AmneziaWG")
		}
		allowed := awgInterfaceFields
		if section == "Peer" {
			allowed = awgPeerFields
		}
		canon := ""
		for _, f := range allowed {
			if strings.EqualFold(f, strings.TrimSpace(key)) {
				canon = f
				break
			}
		}
		if section == "" || canon == "" {
			return Profile{}, errors.New("конфигурация содержит неподдерживаемое поле или секцию AmneziaWG")
		}
		if _, dup := fields[canon]; dup {
			return Profile{}, fmt.Errorf("повторяется параметр %s", canon)
		}
		val, err := normalizeAWGValue(canon, value)
		if err != nil {
			return Profile{}, fmt.Errorf("некорректный параметр AmneziaWG %s", canon)
		}
		fields[canon] = val
		if section == "Interface" && canon != "PrivateKey" && canon != "Address" && canon != "DNS" && canon != "MTU" {
			foundAWG = true
		}
	}
	if err := checkAWGOptions(fields); err != nil {
		return Profile{}, err
	}
	if !foundAWG {
		return Profile{}, errors.New("в конфигурации нет параметров AmneziaWG")
	}
	for _, key := range []string{"PrivateKey", "Address", "PublicKey", "AllowedIPs", "Endpoint"} {
		if fields[key] == "" {
			return Profile{}, fmt.Errorf("в конфигурации AmneziaWG отсутствует %s", key)
		}
	}
	host, port, err := net.SplitHostPort(fields["Endpoint"])
	if err != nil || !validAWGHost(host) {
		return Profile{}, errors.New("неверный адрес AmneziaWG Endpoint")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return Profile{}, errors.New("неверный порт AmneziaWG Endpoint")
	}
	p.Host, p.Ports = host, strconv.FormatUint(n, 10)
	p.AWG.AWGKeys = AWGKeys{PrivateKey: fields["PrivateKey"], PresharedKey: fields["PresharedKey"], HeaderProtectionKey: fields["HeaderProtectionKey"]}
	for _, key := range []string{"PrivateKey", "PresharedKey", "HeaderProtectionKey", "Endpoint"} {
		delete(fields, key)
	}
	block := func(order []string) string {
		var buf strings.Builder
		for _, key := range order {
			if value := fields[key]; value != "" {
				fmt.Fprintf(&buf, "%s = %s\n", key, value)
			}
		}
		return buf.String()
	}
	p.AWG.Interface, p.AWG.Peer = block(awgInterfaceFields), block(awgPeerFields)
	p.Name = p.awgName(name)
	return p, nil
}

// The upstream device rejects overlapping message types and requires a
// full 12-byte nonce in each packet type when header protection is enabled.
func checkAWGOptions(fields map[string]string) error {
	if fields["HeaderProtectionKey"] != "" {
		for _, key := range []string{"S1", "S2", "S3", "S4"} {
			size, _ := strconv.Atoi(fields[key])
			if size < 12 {
				return fmt.Errorf("HeaderProtectionKey требует %s не меньше 12", key)
			}
		}
	}
	if fields["Jmin"] != "" && fields["Jmax"] != "" {
		lo, _ := strconv.Atoi(fields["Jmin"])
		hi, _ := strconv.Atoi(fields["Jmax"])
		if hi < lo {
			return errors.New("в AmneziaWG Jmax меньше Jmin")
		}
	}
	var headers [4][2]uint64
	for i, key := range []string{"H1", "H2", "H3", "H4"} {
		lo, hi := uint64(i+1), uint64(i+1)
		if value := fields[key]; value != "" {
			left, right, hasRange := strings.Cut(value, "-")
			lo, _ = strconv.ParseUint(left, 10, 32)
			hi = lo
			if hasRange {
				hi, _ = strconv.ParseUint(right, 10, 32)
			}
		}
		for _, prior := range headers[:i] {
			if lo <= prior[1] && hi >= prior[0] {
				return errors.New("диапазоны H1–H4 AmneziaWG пересекаются")
			}
		}
		headers[i] = [2]uint64{lo, hi}
	}
	return nil
}

func validAWGHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Zone() == ""
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeAWGValue(key, value string) (string, error) {
	bad := errors.New("invalid value")
	switch key {
	case "PrivateKey", "PublicKey", "PresharedKey", "HeaderProtectionKey":
		b, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(b) != 32 || bytes.Equal(b, zeroAWGKey[:]) {
			return "", bad
		}
	case "Address", "AllowedIPs", "DNS":
		list := strings.Split(value, ",")
		for i, s := range list {
			s = strings.TrimSpace(s)
			if key == "DNS" {
				addr, err := netip.ParseAddr(s)
				if err != nil || addr.Zone() != "" {
					return "", bad
				}
				list[i] = addr.String()
				continue
			}
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				return "", bad
			}
			list[i] = prefix.String()
		}
		return strings.Join(list, ", "), nil
	case "Endpoint":
	case "I1", "I2", "I3", "I4", "I5":
		if len(value) > 16384 || !strings.HasPrefix(value, "<") || !strings.HasSuffix(value, ">") || !safeIPacket(value) {
			return "", bad
		}
	case "RandomTrailers", "DisableCookies":
		switch strings.ToLower(value) {
		case "on", "true", "1":
			return "on", nil
		case "off", "false", "0":
			return "off", nil
		default:
			return "", bad
		}
	default:
		minV, maxV, ranged := uint64(0), uint64(65535), true
		switch key {
		case "MTU":
			minV, maxV, ranged = 576, 9000, false
		case "Jc":
			maxV, ranged = 128, false
		case "Jmin", "Jmax", "S1", "S2", "S3", "S4":
			maxV, ranged = 4096, false
		case "ContentPaddingAddition":
			maxV = 4096
		case "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts":
			minV = 1
		case "H1", "H2", "H3", "H4":
			maxV = 1<<32 - 1
		}
		a, b, hasRange := strings.Cut(value, "-")
		low, err := strconv.ParseUint(a, 10, 32)
		if err != nil || low < minV || low > maxV {
			return "", bad
		}
		if hasRange {
			high, err := strconv.ParseUint(b, 10, 32)
			if !ranged || err != nil || high < low || high > maxV {
				return "", bad
			}
		}
	}
	return value, nil
}

func (p Profile) AWGConfig() string {
	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintln(&b, "PrivateKey =", p.AWG.PrivateKey)
	if p.AWG.HeaderProtectionKey != "" {
		fmt.Fprintln(&b, "HeaderProtectionKey =", p.AWG.HeaderProtectionKey)
	}
	b.WriteString(p.AWG.Interface)
	fmt.Fprintln(&b, "\n[Peer]")
	b.WriteString(p.AWG.Peer)
	if p.AWG.PresharedKey != "" {
		fmt.Fprintln(&b, "PresharedKey =", p.AWG.PresharedKey)
	}
	fmt.Fprintln(&b, "Endpoint =", net.JoinHostPort(p.Host, p.Ports))
	return b.String()
}

func (p Profile) validateAWG() error {
	parsed, err := ParseAWGConfig(p.AWGConfig())
	if err != nil {
		return err
	}
	normalized := p
	normalized.Normalize()
	if normalized != p || parsed.AWG != p.AWG || parsed.Host != p.Host || parsed.Ports != p.Ports {
		return errors.New("некорректные поля профиля AmneziaWG")
	}
	return nil
}

// The upstream chain accepts signed lengths and allocates the resulting
// packet in its sending goroutine. Bound the expanded size before IpcSet.
func safeIPacket(spec string) bool {
	total := 0
	for {
		_, tail, ok := strings.Cut(spec, "<")
		if !ok {
			return true
		}
		tag, rest, ok := strings.Cut(tail, ">")
		if !ok {
			return false
		}
		fields := strings.Fields(tag)
		if len(fields) == 0 {
			return false
		}
		switch fields[0] {
		case "r", "rd", "rc", "dz":
			if len(fields) != 2 {
				return false
			}
			n, err := strconv.ParseUint(fields[1], 10, 16)
			if err != nil {
				return false
			}
			total += int(n)
		case "b":
			if len(fields) != 2 {
				return false
			}
			data, err := hex.DecodeString(strings.TrimPrefix(fields[1], "0x"))
			if err != nil || len(data) == 0 {
				return false
			}
			total += len(data)
		case "t":
			total += 4
		case "d", "ds": // Empty payload in initiation packets.
		default:
			return false
		}
		if total > 65507 {
			return false
		}
		spec = rest
	}
}
