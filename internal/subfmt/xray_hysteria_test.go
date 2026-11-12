package subfmt

import (
	"strings"
	"testing"
)

const xrayHy2 = `{"tag":"hy-out","protocol":"hysteria","settings":{"version":2,"address":"node.example","port":443},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"demo:pass/@","udpIdleTimeout":60},"tlsSettings":{"serverName":"sni.example","alpn":["h3"],"pinnedPeerCertSha256":"` + demoPin + `"},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"demo/obfs"}}]}}}`
const demoPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestXrayHysteria2PanelAndBalancer(t *testing.T) {
	second := strings.Replace(xrayHy2, "node.example", "second.example", 1)
	body := `[{"remarks":"First","outbounds":[` + xrayHy2 + `,{"protocol":"freedom"}]},
		{"remarks":"Second","outbounds":[` + second + `]},
		{"remarks":"Balancer","outbounds":[` + strings.Replace(xrayHy2, "hy-out", "bal-1", 1) + `,` + strings.Replace(second, "hy-out", "bal-2", 1) + `]}]`
	r, ok := Convert([]byte(body))
	_, links := parsed(t, r)
	if !ok || len(links) != 4 || len(r.Skipped) != 0 || len(r.Warnings) != 0 {
		t.Fatalf("got %d links, %d skips, %d warnings", len(links), len(r.Skipped), len(r.Warnings))
	}
	for i, name := range []string{"First", "Second", "bal-1", "bal-2"} {
		if links[i].Name != name {
			t.Fatal("outbound name lost")
		}
	}
	for i := 0; i < 2; i++ {
		a, b := links[i], links[i+2]
		a.Name, b.Name = "", ""
		if a != b || a.Auth != "demo:pass/@" || a.Ports != "443" || a.ObfsType != "salamander" || a.ObfsPassword != "demo/obfs" || a.PinSHA256 != demoPin || a.SNI != "sni.example" {
			t.Fatal("connection parameters lost")
		}
	}
}

func TestXrayHysteriaInvalidKeepsOtherProxies(t *testing.T) {
	for _, pair := range [][2]string{{`"version":2`, `"version":1`}, {`"port":443`, `"port":0`}, {`"network":"hysteria"`, `"network":"ws"`}, {`"security":"tls"`, `"security":"none"`}, {demoPin, "bad-pin"}, {`"type":"salamander"`, `"type":"unknown"`}} {
		bad := strings.Replace(xrayHy2, pair[0], pair[1], 1)
		r, _ := Convert([]byte(`{"outbounds":[` + bad + `,` + xrayHy2 + `]}`))
		if len(r.Links) != 1 || len(r.Skipped) != 1 || len(r.Other) != 0 || len(r.Errors) != 1 {
			t.Fatalf("invalid outbound was lost or accepted (%s)", pair[0])
		}
	}
}

func TestXrayHysteriaPinsAndHopping(t *testing.T) {
	for _, mask := range []string{
		`{"udp":[{"type":"udphop","settings":{"mode":"intervallocal,intervalremote","interval":"30","remoteIPs":[""],"remotePorts":"20000-20100"}}]}`,
		`{"quicParams":{"udpHop":{"interval":30,"ports":"20000-20100"}}}`,
	} {
		// Older panels emit a base64-encoded DER certificate hash.
		ob := strings.Replace(xrayHy2, `"`+demoPin+`"`, `["ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="]`, 1)
		ob = strings.Replace(ob, `{"udp":[{"type":"salamander","settings":{"password":"demo/obfs"}}]}`, mask, 1)
		r, _ := Convert([]byte(`{"outbounds":[` + ob + `]}`))
		_, links := parsed(t, r)
		if len(links) != 1 || links[0].PinSHA256 != demoPin || links[0].Ports != "20000-20100" || links[0].HopInterval != "30s" || len(r.Warnings) > 0 {
			t.Fatal("port hopping or certificate pin lost")
		}
	}
}
