package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
)

// A new Xray core is tested with the configs of the user's VLESS servers
// and of the samples; the error names the server and never its ID.
func TestTestXray(t *testing.T) {
	c, _ := newCtl(t)
	p, _, err := hysteria.ParseURI(vlessLink)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "v1"
	c.mu.Lock()
	c.profiles.List = append(c.profiles.List, p)
	c.mu.Unlock()
	var seen []string
	c.xrayTest = func(path string, cfg []byte) error {
		if path != `C:\new\xray.exe` {
			t.Fatalf("path %s", path)
		}
		seen = append(seen, string(cfg))
		if strings.Contains(string(cfg), `"www.example.org"`) {
			return errors.New(`unknown field in user 5f0b7c1e-1234-4abc-9def-0123456789ab`)
		}
		return nil
	}
	err = c.TestXray(`C:\new\xray.exe`)
	if err == nil || !strings.HasPrefix(err.Error(), "«NL»: ") || strings.Contains(err.Error(), "5f0b7c1e") {
		t.Fatalf("%v", err)
	}
	if len(seen) != len(xraySamples)+1 {
		t.Fatalf("%d configs tested", len(seen))
	}
	// The pinned server is tested as it runs: the IP dialed, the name in TLS.
	if last := seen[len(seen)-1]; !strings.Contains(last, `"address": "203.0.113.5"`) || !strings.Contains(last, `"serverName": "www.example.org"`) {
		t.Fatalf("%s", last)
	}
	c.xrayTest = func(string, []byte) error { return nil }
	if err := c.TestXray(`C:\new\xray.exe`); err != nil {
		t.Fatal(err)
	}
}
