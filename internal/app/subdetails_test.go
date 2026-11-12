package app

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestPanelPlainSubscription(t *testing.T) {
	awg := "[Interface]\r\nPrivateKey = artificial-secret\r\nJc = 4\r\n[Peer]\r\nPublicKey = example\r\n"
	query := url.Values{
		"type": {"xhttp"}, "mode": {"auto"}, "security": {"reality"}, "sni": {"tls.example"},
		"pbk": {strings.Repeat("A", 43)}, "support-x25519mlkem768": {"true"},
		"extra":           {`{"mode":"auto","xPaddingBytes":"100-1000","sessionIDKey":"demo","sessionKey":"demo"}`},
		"x_padding_bytes": {"100-1000"}, "unusedEmpty": {""},
	}
	body := "vless://test@example.invalid:443?" + query.Encode() + "#XHTTP\nhy2://demo@example.invalid:443#H2\nvpn://" + base64.RawURLEncoding.EncodeToString([]byte(awg))
	l, err := parseSubscription([]byte(base64.StdEncoding.EncodeToString([]byte(body))))
	if err != nil {
		t.Fatal(err)
	}
	d := importReport(l)
	if !l.Base64 || len(d.Profiles) != 2 || len(d.Duplicates) != 0 || len(d.Skipped) != 1 || d.Skipped[0].Protocol != "AmneziaWG" || len(d.Warnings) != 0 {
		t.Fatalf("unexpected report: %+v", d)
	}
	p := l.Profiles[0].VLESS
	if p.Mode != "auto" || !strings.Contains(p.Extra, `"xPaddingBytes":"100-1000"`) || !strings.Contains(p.Extra, `"sessionIDKey":"demo"`) {
		t.Fatal("XHTTP settings lost")
	}
	// A plain WireGuard config or a marker hidden in a comment is inconclusive.
	for _, other := range []string{strings.ReplaceAll(awg, "Jc = 4", "# Jc = 4"), "[Interface]\nJc = 1\n"} {
		budget := maxSubBody
		if amneziaWG("vpn://"+base64.RawURLEncoding.EncodeToString([]byte(other)), &budget) {
			t.Fatal("false AWG detection")
		}
	}
}

func TestSubscriptionWarningsHaveSafeProfileContext(t *testing.T) {
	input := "vless://test@one.invalid:443?type=httpupgrade&security=tls&allowInsecure=1&private-marker=value#httpupgrade\nvless://test@two.invalid:443?type=xhttp&security=tls&extra=" + url.QueryEscape(`{"downloadSettings":{"tlsSettings":{"masterKeyLog":"test-secret"}}}`) + "#Panel"
	d := importReport(ParseLinks(input))
	text := strings.Join(d.Warnings, "\n")
	if len(d.Warnings) != 3 || !strings.Contains(text, "httpupgrade") || !strings.Contains(text, "masterKeyLog") || !strings.Contains(text, "Panel") || !strings.Contains(text, "сертификат") || strings.Contains(text, "Параметр up ") || strings.Contains(text, "private-marker") || strings.Contains(text, "test-secret") {
		t.Fatal(text)
	}
}

func TestSubscriptionDetailsSnapshot(t *testing.T) {
	c, _ := newCtl(t)
	cfg := []byte(`{"containers":[{"container":"amnezia-awg","awg":{"privateKey":"private-marker"}}]}`)
	var packed bytes.Buffer
	binary.Write(&packed, binary.BigEndian, uint32(len(cfg)))
	w := zlib.NewWriter(&packed)
	w.Write(cfg)
	w.Close()
	var lines []string
	for i := 1; i <= 6; i++ {
		lines = append(lines, fmt.Sprintf("hy2://test-password@node%d.invalid:443#Node%d", i, i))
	}
	lines = append(lines, vlessLink, "vpn://"+base64.RawURLEncoding.EncodeToString(packed.Bytes()))
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
	sub := addSub(t, c, &body)
	verify := func(c *Controller) {
		t.Helper()
		d, err := c.SubscriptionDetails(sub.ID)
		if err != nil || len(d.Profiles) != 7 || d.Profiles[6].Protocol != "VLESS" || d.Profiles[0].Name != "Node1" || d.Profiles[0].Protocol != "Hysteria 2" ||
			len(d.Skipped) != 1 || d.Skipped[0].Protocol != "AmneziaWG" || d.Skipped[0].Reason == "" || d.Partial {
			t.Fatalf("unexpected import report: %+v, %v", d, err)
		}
		report, _ := json.Marshal(d)
		for _, secret := range []string{"test-password", "private-marker", "://", base64.RawURLEncoding.EncodeToString(packed.Bytes())} {
			if bytes.Contains(report, []byte(secret)) {
				t.Fatal("import report leaked source data")
			}
		}
	}
	verify(c)
	body = strings.Join([]string{lines[0], lines[0] + "-copy", "vpn://opaque-secret#Unknown", "other://secret@private.invalid#Other", "hy2://pw@domain.invalid:bad-secret#Malformed"}, "\n")
	if _, err := c.UpdateSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	d, err := c.SubscriptionDetails(sub.ID)
	if err != nil || len(d.Profiles) != 1 || len(d.Duplicates) != 1 || len(d.Skipped) != 3 || d.Skipped[0].Protocol == "AmneziaWG" {
		t.Fatalf("updated report: %+v, %v", d, err)
	}
	report, _ := json.Marshal(d)
	if bytes.Contains(report, []byte("secret")) {
		t.Fatal("raw input in a skip reason")
	}
	if _, err := c.RollbackSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := newCtlAt(t, c.Store)
	verify(reloaded)
	c.Store.DeleteSnapshots(sub.ID)
	d, err = c.SubscriptionDetails(sub.ID)
	if err != nil || !d.Partial || len(d.Profiles) != 7 || len(d.Skipped) != 1 {
		t.Fatal("missing legacy snapshot lost saved summary")
	}
}
