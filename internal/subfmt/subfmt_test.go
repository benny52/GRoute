package subfmt

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/vless"
)

const (
	uuid = "5f0b7c1e-1234-4abc-9def-0123456789ab"
	pbk  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

// parsed reads r's links back (the format of the links is vless's and
// hy2uri's own, tested there).
func parsed(t *testing.T, r Result) (vl []vless.Link, hy []hy2uri.Link) {
	t.Helper()
	for _, l := range r.Links {
		switch {
		case strings.HasPrefix(l, "vless://"):
			v, _, err := vless.Parse(l)
			if err != nil {
				t.Fatalf("%s: %v", l, err)
			}
			vl = append(vl, v)
		case strings.HasPrefix(l, "hysteria2://"):
			h, _, err := hy2uri.Parse(l)
			if err != nil {
				t.Fatalf("%s: %v", l, err)
			}
			hy = append(hy, h)
		default:
			t.Fatalf("link %s", l)
		}
	}
	return vl, hy
}

func TestClash(t *testing.T) {
	body := `mixed-port: 7890
proxies:
  - name: "NL Reality"
    type: vless
    server: nl.example.com
    port: 443
    uuid: ` + uuid + `
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.org
    client-fingerprint: chrome
    reality-opts:
      public-key: ` + pbk + `
      short-id: 6ba85179e30d4fc2
  - name: DE WS
    type: vless
    server: de.example.com
    port: 8443
    uuid: ` + uuid + `
    tls: true
    servername: cdn.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - name: FI hy2
    type: hysteria2
    server: fi.example.com
    port: 443
    ports: 20000-30000
    hop-interval: 30
    password: pw
    obfs: salamander
    obfs-password: ob
    sni: fi.example.com
  - {name: old, type: vmess, server: a.example.com, port: 1}
  - {name: DIRECT, type: direct}
  - name: broken
    type: vless
    server: x.example.com
    port: 443
    uuid: ` + uuid + `
    network: h2
    tls: true
proxy-groups:
  - {name: auto, type: url-test, proxies: [NL Reality]}
`
	r, ok := Convert([]byte(body))
	if !ok || r.Format != "Clash" {
		t.Fatalf("%v %+v", ok, r)
	}
	vl, hy := parsed(t, r)
	if len(vl) != 2 || len(hy) != 1 {
		t.Fatalf("%+v", r)
	}
	want := vless.Link{Name: "NL Reality", Host: "nl.example.com", Port: 443, Settings: vless.Settings{ID: uuid, Flow: vless.FlowVision,
		Security: "reality", SNI: "www.example.org", Fingerprint: "chrome", PublicKey: pbk, ShortID: "6ba85179e30d4fc2"}}
	if !reflect.DeepEqual(vl[0], want) {
		t.Errorf("%+v\nwant %+v", vl[0], want)
	}
	if s := vl[1].Settings; vl[1].Port != 8443 || s.Network != "ws" || s.Path != "/ws" || s.Host != "cdn.example.com" || s.SNI != "cdn.example.com" {
		t.Errorf("%+v", vl[1])
	}
	if h := hy[0]; h.Name != "FI hy2" || h.Ports != "443,20000-30000" || h.Auth != "pw" || h.ObfsType != "salamander" || h.ObfsPassword != "ob" || h.HopInterval != "30s" {
		t.Errorf("%+v", h)
	}
	if r.Other["vmess"] != 1 || len(r.Other) != 1 {
		t.Errorf("other %v", r.Other)
	}
	if len(r.Errors) != 1 || !strings.HasPrefix(r.Errors[0], "broken: ") || len(r.Warnings) != 1 || !strings.HasPrefix(r.Warnings[0], "DE WS: skip-cert-verify") {
		t.Errorf("errors %q warnings %q", r.Errors, r.Warnings)
	}
}

func TestSingBox(t *testing.T) {
	body := `{
  "log": {"level": "warn"},
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["NL", "WS", "FI"]},
    {"type": "vless", "tag": "NL", "server": "nl.example.com", "server_port": 443, "uuid": "` + uuid + `", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.example.org", "utls": {"enabled": true, "fingerprint": "firefox"},
             "reality": {"enabled": true, "public_key": "` + pbk + `", "short_id": "ab"}}},
    {"type": "vless", "tag": "WS", "server": "203.0.113.4", "server_port": 443, "uuid": "` + uuid + `",
     "tls": {"enabled": true, "server_name": "cdn.example.com", "alpn": ["h2", "http/1.1"]},
     "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}}},
    {"type": "vless", "tag": "GRPC", "server": "g.example.com", "server_port": 443, "uuid": "` + uuid + `",
     "tls": {"enabled": true}, "transport": {"type": "grpc", "service_name": "svc"}},
    {"type": "hysteria2", "tag": "FI", "server": "fi.example.com", "server_port": 443, "server_ports": ["20000:30000"],
     "hop_interval": "30s", "password": "pw", "obfs": {"type": "salamander", "password": "ob"}, "tls": {"enabled": true, "server_name": "fi.example.com"}},
    {"type": "trojan", "tag": "T", "server": "t.example.com", "server_port": 443},
    {"type": "direct", "tag": "direct"}
  ]
}`
	r, ok := Convert([]byte(body))
	if !ok || r.Format != "sing-box" {
		t.Fatalf("%v %+v", ok, r)
	}
	vl, hy := parsed(t, r)
	if len(vl) != 3 || len(hy) != 1 || r.Other["trojan"] != 1 || len(r.Errors) != 0 {
		t.Fatalf("%+v", r)
	}
	if s := vl[0].Settings; vl[0].Name != "NL" || s.Security != "reality" || s.Fingerprint != "firefox" || s.ShortID != "ab" || s.Flow != vless.FlowVision {
		t.Errorf("%+v", vl[0])
	}
	if s := vl[1].Settings; vl[1].Host != "203.0.113.4" || s.Network != "ws" || s.Host != "cdn.example.com" || s.ALPN != "h2,http/1.1" {
		t.Errorf("%+v", vl[1])
	}
	if s := vl[2].Settings; s.Network != "grpc" || s.ServiceName != "svc" || s.Security != "tls" {
		t.Errorf("%+v", vl[2])
	}
	if h := hy[0]; h.Ports != "443,20000-30000" || h.HopInterval != "30s" || h.SNI != "fi.example.com" {
		t.Errorf("%+v", h)
	}
}

func TestXrayList(t *testing.T) {
	// A panel's "Xray JSON" subscription: one full config per server.
	body := `[
  {"remarks": "🇳🇱 NL", "outbounds": [
    {"tag": "proxy", "protocol": "vless",
     "settings": {"vnext": [{"address": "nl.example.com", "port": 443, "users": [{"id": "` + uuid + `", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
     "streamSettings": {"network": "raw", "security": "reality",
       "realitySettings": {"serverName": "www.example.org", "fingerprint": "chrome", "password": "` + pbk + `", "shortId": "ab", "spiderX": "/"}}},
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}]},
  {"remarks": "DE xhttp", "outbounds": [
    {"tag": "proxy", "protocol": "vless",
     "settings": {"address": "de.example.com", "port": 443, "id": "` + uuid + `", "encryption": "none"},
     "streamSettings": {"network": "xhttp", "security": "tls",
       "tlsSettings": {"serverName": "de.example.com", "alpn": ["h2"], "fingerprint": "chrome"},
       "xhttpSettings": {"path": "/x", "host": "de.example.com", "mode": "packet-up", "xPaddingBytes": "100-1000", "extra": {"noGRPCHeader": true}},
       "sockopt": {"dialerProxy": "fragment"}}},
    {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello"}}}]},
  {"remarks": "VM", "outbounds": [{"tag": "proxy", "protocol": "vmess"}]}
]`
	r, ok := Convert([]byte(body))
	if !ok || r.Format != "Xray" {
		t.Fatalf("%v %+v", ok, r)
	}
	vl, _ := parsed(t, r)
	if len(vl) != 2 || r.Other["vmess"] != 1 || len(r.Errors) != 0 {
		t.Fatalf("%+v", r)
	}
	if s := vl[0].Settings; vl[0].Name != "🇳🇱 NL" || s.PublicKey != pbk || s.SpiderX != "/" || s.Network != "" {
		t.Errorf("%+v", vl[0])
	}
	s := vl[1].Settings
	if vl[1].Name != "DE xhttp" || s.Network != "xhttp" || s.Mode != "packet-up" || s.Path != "/x" || s.ALPN != "h2" {
		t.Errorf("%+v", vl[1])
	}
	if s.Extra != `{"noGRPCHeader":true,"xPaddingBytes":"100-1000"}` {
		t.Errorf("extra %s", s.Extra)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "sockopt") {
		t.Errorf("warnings %q", r.Warnings)
	}
}

func TestNotAConfig(t *testing.T) {
	for _, body := range []string{"", "vless://a@b:1", "<html></html>", "just text", `{"a":1}`, `[1,2]`, "a: b\n"} {
		if _, ok := Convert([]byte(body)); ok {
			t.Errorf("%q read as a config", body)
		}
	}
}
