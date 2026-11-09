package vless

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

// hostileExtra has what a link must not hand xray.exe: a file for TLS
// keys, certificate files, socket options, a nested extra.
const hostileExtra = `{"xPaddingBytes":"100-1000","sockopt":{"mark":7},
 "downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls",
  "sockopt":{"interface":"eth0"},
  "tlsSettings":{"serverName":"dl.example.com","alpn":["h2"],"masterKeyLog":"C:\\Windows\\win.ini",
   "certificates":[{"certificateFile":"C:\\x.pem"}],"echSockopt":{"mark":1},"allowInsecure":true},
  "realitySettings":{"publicKey":"pk","masterKeyLog":"x","privateKey":"k"},
  "xhttpSettings":{"path":"/d","downloadSettings":{},"extra":{"a":1}}}}`

func TestCleanExtra(t *testing.T) {
	got, dropped, err := CleanExtra(hostileExtra)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"masterKeyLog", "certificates", "sockopt", "echSockopt", "allowInsecure", "privateKey", "win.ini", `"extra"`} {
		if strings.Contains(got, bad) {
			t.Errorf("%s kept: %s", bad, got)
		}
	}
	for _, good := range []string{`"xPaddingBytes":"100-1000"`, `"address":"dl.example.com"`, `"serverName":"dl.example.com"`, `"publicKey":"pk"`, `"path":"/d"`} {
		if !strings.Contains(got, good) {
			t.Errorf("%s dropped: %s", good, got)
		}
	}
	want := []string{"downloadSettings.realitySettings.masterKeyLog", "downloadSettings.realitySettings.privateKey",
		"downloadSettings.sockopt", "downloadSettings.tlsSettings.allowInsecure", "downloadSettings.tlsSettings.certificates",
		"downloadSettings.tlsSettings.echSockopt", "downloadSettings.tlsSettings.masterKeyLog",
		"downloadSettings.xhttpSettings.downloadSettings", "downloadSettings.xhttpSettings.extra", "sockopt"}
	slices.Sort(dropped)
	if !slices.Equal(dropped, want) {
		t.Errorf("dropped %q", dropped)
	}
	if _, _, err := CleanExtra("[1]"); err == nil {
		t.Error("an array taken as extra")
	}
	if got, dropped, err := CleanExtra(`{"sockopt":{}}`); err != nil || got != "" || len(dropped) != 1 {
		t.Errorf("nothing left: %q %q %v", got, dropped, err)
	}
}

// A link and settings saved before CleanExtra: neither reaches xray.exe
// with the hostile keys.
func TestExtraFromLinkAndSaved(t *testing.T) {
	link := "vless://" + testID + "@example.com:443?type=xhttp&security=tls&path=%2Fx&extra=" + url.QueryEscape(hostileExtra)
	l, warnings, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(l.Settings.Extra, "masterKeyLog") || !strings.Contains(strings.Join(warnings, "\n"), "downloadSettings.tlsSettings.masterKeyLog") {
		t.Errorf("%s %q", l.Settings.Extra, warnings)
	}
	m := config(t, Settings{ID: testID, Network: "xhttp", Security: "tls", Path: "/x", Extra: hostileExtra}, Run{Host: "example.com", Port: 443})
	ds := at(t, m, "outbounds", 0, "streamSettings", "xhttpSettings", "extra", "downloadSettings")
	if _, has := ds.(map[string]any)["sockopt"]; has {
		t.Errorf("sockopt in %v", ds)
	}
	if tls := at(t, ds, "tlsSettings").(map[string]any); tls["masterKeyLog"] != nil || tls["serverName"] != "dl.example.com" {
		t.Errorf("tlsSettings %v", tls)
	}
}
