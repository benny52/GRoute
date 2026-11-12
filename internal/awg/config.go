// Package awg runs AmneziaWG inside GRoute's userspace network stack.
package awg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

type deviceConfig struct {
	uapi           string
	public         device.NoisePublicKey
	addresses, dns []netip.Addr
	mtu            int
}

var uapiNames = map[string]string{
	"privatekey": "private_key", "publickey": "public_key", "presharedkey": "preshared_key",
	"headerprotectionkey": "header_protection_key", "persistentkeepalive": "persistent_keepalive_interval",
	"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time",
	"rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout",
	"maxhandshakeattempts": "max_handshake_attempts", "randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
	"jc": "jc", "jmin": "jmin", "jmax": "jmax", "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
}

// configForDevice translates the validated canonical wg-quick profile to
// UAPI. A peer's public_key must precede all its options, independently of
// their order in the file. Only the outer endpoint uses the host resolver.
func configForDevice(conf string, pinned netip.Addr) (deviceConfig, error) {
	cfg := deviceConfig{mtu: 1420}
	var iface, peer strings.Builder
	var pub string
	for line := range strings.SplitSeq(conf, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch key {
		case "address", "dns":
			for field := range strings.SplitSeq(value, ",") {
				field = strings.TrimSpace(field)
				ip, err := netip.ParseAddr(field)
				if err != nil && key == "address" {
					if prefix, err := netip.ParsePrefix(field); err == nil {
						ip = prefix.Addr()
					}
				}
				if !ip.IsValid() {
					return cfg, errors.New("AmneziaWG: некорректный IP в " + key)
				}
				if key == "address" {
					cfg.addresses = append(cfg.addresses, ip)
				} else {
					cfg.dns = append(cfg.dns, ip)
				}
			}
		case "mtu":
			n, err := strconv.Atoi(value)
			if err != nil || n < 576 || n > 9000 {
				return cfg, errors.New("AmneziaWG: некорректный MTU")
			}
			cfg.mtu = n
		case "allowedips":
			for prefix := range strings.SplitSeq(value, ",") {
				peer.WriteString("allowed_ip=" + strings.TrimSpace(prefix) + "\n")
			}
		case "endpoint":
			_, port, err := net.SplitHostPort(value)
			if err != nil || !pinned.IsValid() {
				return cfg, errors.New("AmneziaWG: некорректный endpoint")
			}
			peer.WriteString("endpoint=" + net.JoinHostPort(pinned.String(), port) + "\n")
		default:
			name, ok := uapiNames[key]
			if !ok {
				return cfg, errors.New("AmneziaWG: неизвестный параметр профиля")
			}
			if key == "randomtrailers" || key == "disablecookies" {
				switch strings.ToLower(value) {
				case "on", "yes":
					value = "true"
				case "off", "no":
					value = "false"
				}
			}

			if strings.HasSuffix(name, "_key") {
				raw, err := base64.StdEncoding.DecodeString(value)
				if err != nil || len(raw) != 32 {
					return cfg, errors.New("AmneziaWG: некорректный ключ")
				}
				value = hex.EncodeToString(raw)
				if key == "publickey" {
					copy(cfg.public[:], raw)
					pub = value
					continue
				}
			}
			w := &iface
			if key == "presharedkey" || key == "persistentkeepalive" {
				w = &peer
			}
			w.WriteString(name + "=" + value + "\n")
		}
	}
	if len(cfg.addresses) == 0 || pub == "" {
		return cfg, errors.New("AmneziaWG: неполный профиль")
	}
	cfg.uapi = iface.String() + "public_key=" + pub + "\n" + peer.String()
	return cfg, nil
}
