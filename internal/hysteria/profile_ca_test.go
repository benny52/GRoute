package hysteria

import (
	"runtime"
	"testing"
)

// The CA file Hysteria reads with HyRoute's rights is a local file:
// never a relative, network or device path.
func TestCAPath(t *testing.T) {
	ok, bad := []string{"/etc/hyroute/ca.pem", `C:\ca.pem`}, []string{"ca.pem", " /etc/ca.pem", `\\host\share\ca.pem`}
	if runtime.GOOS == "windows" {
		ok, bad = []string{`C:\certs\ca.pem`}, []string{"ca.pem", `\\host\share\ca.pem`, `\\?\C:\ca.pem`, `\ca.pem`, `C:/ca.pem`}
	}
	for _, ca := range ok {
		p := Profile{Host: "vpn.example.com", Protocol: ProtoHysteria2, Ports: "443", TLS: TLS{CA: ca}}
		if err := p.Validate(); err != nil {
			t.Errorf("%q: %v", ca, err)
		}
	}
	for _, ca := range bad {
		p := Profile{Host: "vpn.example.com", Protocol: ProtoHysteria2, Ports: "443", TLS: TLS{CA: ca}}
		if err := p.Validate(); err == nil {
			t.Errorf("%q accepted", ca)
		}
	}
}
