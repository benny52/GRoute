package subfmt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hy2uri"
)

// 3x-ui's JSON subscription puts the endpoint in the outbound and the
// credentials in the Hysteria transport (internal/sub/json_service.go).
func (r *Result) xrayHysteria(name string, raw json.RawMessage) {
	var ob struct {
		ProxySettings struct{ Tag string }
		Settings      struct {
			Address       string
			Port, Version int
		}
		Stream struct {
			Network, Security string
			Sockopt           struct{ DialerProxy string }
			Hysteria          struct {
				Version int
				Auth    string
			} `json:"hysteriaSettings"`
			TLS struct {
				ServerName, ECHConfigList                  string
				PinnedPeerCertSha256, VerifyPeerCertByName json.RawMessage
				AllowInsecure, DisableSystemRoot           bool
				Certificates                               []json.RawMessage
			} `json:"tlsSettings"`
			FinalMask struct {
				UDP []struct {
					Type     string
					Settings json.RawMessage
				}
				QUICParams map[string]json.RawMessage
			}
		} `json:"streamSettings"`
	}
	if json.Unmarshal(raw, &ob) != nil {
		r.fail(name, errors.New("некорректная структура JSON Hysteria"))
		return
	}
	st, ss := ob.Settings, ob.Stream
	if ob.ProxySettings.Tag != "" || ss.Sockopt.DialerProxy != "" {
		r.fail(name, errors.New("неподдерживаемая цепочка прокси Hysteria 2"))
		return
	}
	if st.Version != 2 || ss.Hysteria.Version != 2 {
		r.fail(name, errors.New("поддерживается только Hysteria версии 2"))
		return
	}
	if ss.Network != "hysteria" || ss.Security != "tls" {
		r.fail(name, errors.New("нужен транспорт hysteria с TLS"))
		return
	}
	if st.Port < 1 || st.Port > 65535 || st.Address == "" || strings.ContainsAny(st.Address, "/@?# \t\n\r") {
		r.fail(name, errors.New("некорректный адрес или порт сервера"))
		return
	}
	t := ss.TLS
	l := hy2uri.Link{Name: name, Host: st.Address, Ports: strconv.Itoa(st.Port), Auth: ss.Hysteria.Auth,
		SNI: t.ServerName, ECH: t.ECHConfigList, Insecure: t.AllowInsecure}
	pin, single := xraySingleValue(t.PinnedPeerCertSha256)
	pin, ok := xrayHysteriaPin(pin)
	if !single || !ok {
		r.fail(name, errors.New("невозможно перенести pinnedPeerCertSha256 в Hysteria 2"))
		return
	}
	l.PinSHA256 = pin
	verify, ok := xraySingleValue(t.VerifyPeerCertByName)
	if !ok || verify != "" && (verify != firstNonEmpty(l.SNI, l.Host) || l.Insecure) || t.DisableSystemRoot || len(t.Certificates) > 0 {
		r.fail(name, errors.New("невозможно перенести проверку сертификата TLS в Hysteria 2"))
		return
	}
	// Xray's HTTP/3 client replaces tlsSettings.alpn with h3 before dialing.
	// The native Hysteria client also negotiates h3.
	var hop json.RawMessage
	for _, m := range ss.FinalMask.UDP {
		switch m.Type {
		case "salamander":
			var s struct {
				Password   string
				PacketSize json.RawMessage
			}
			if json.Unmarshal(m.Settings, &s) != nil || s.Password == "" || l.ObfsType != "" {
				r.fail(name, errors.New("некорректная маска salamander для Hysteria 2"))
				return
			}
			if len(s.PacketSize) > 0 && string(s.PacketSize) != "null" && string(s.PacketSize) != `""` {
				r.fail(name, errors.New("настройка packetSize маски salamander не переносится"))
				return
			}
			l.ObfsType, l.ObfsPassword = "salamander", s.Password
		case "udphop":
			if hop != nil {
				r.fail(name, errors.New("несколько масок udphop не поддерживаются"))
				return
			}
			hop = m.Settings
		default:
			r.fail(name, errors.New("неподдерживаемая UDP-маска Hysteria 2"))
			return
		}
	}
	// Before Xray 26.9.9 the remote port range lived under quicParams.udpHop.
	if hop == nil {
		hop = ss.FinalMask.QUICParams["udpHop"]
	}
	delete(ss.FinalMask.QUICParams, "udpHop")
	if err := applyHysteriaHop(&l, hop); err != nil {
		r.fail(name, err)
		return
	}
	if len(ss.FinalMask.QUICParams) > 0 {
		r.warn(name, "Hysteria 2: используются штатные параметры QUIC клиента вместо quicParams Xray")
	}
	r.hy2Link(l)
}

// Xray accepts a list of pins/names (array or comma-separated). A Hysteria
// profile has one pin and verifies the SNI; never silently discard a constraint.
func xraySingleValue(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", true
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "", false
		}
		values = strings.Split(value, ",")
	}
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

func xrayHysteriaPin(pin string) (string, bool) {
	if pin == "" {
		return "", true
	}
	if hy2uri.ValidPin(pin) {
		return strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(pin)), true
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(pin); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), true
		}
	}
	return "", false
}

func applyHysteriaHop(l *hy2uri.Link, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var h struct {
		Mode, RemotePorts, Ports string
		Interval, RemoteIPs      json.RawMessage
	}
	if json.Unmarshal(raw, &h) != nil {
		return errors.New("некорректные параметры смены порта Hysteria 2")
	}
	ip, single := xraySingleValue(h.RemoteIPs)
	if !single || ip != "" && ip != l.Host {
		return errors.New("неподдерживаемая конфигурация смены адреса или порта Hysteria 2")
	}
	ports := firstNonEmpty(h.RemotePorts, h.Ports)
	if ports == "" {
		return nil
	}
	if h.Mode != "" && h.Mode != "intervalremote" && h.Mode != "intervallocal,intervalremote" {
		return errors.New("неподдерживаемый режим смены порта Hysteria 2")
	}
	if _, err := hy2uri.ParsePorts(ports); err != nil {
		return errors.New("некорректный диапазон портов Hysteria 2")
	}
	l.Ports = hy2uri.NormalizePorts(ports)
	if len(h.Interval) > 0 && string(h.Interval) != "null" {
		v := strings.Trim(string(h.Interval), "\"")
		n, err := strconv.Atoi(v)
		if err != nil || n < 5 || n > 3600 {
			return errors.New("неподдерживаемый интервал смены порта Hysteria 2")
		}
		l.HopInterval = strconv.Itoa(n) + "s"
	}
	return nil
}
