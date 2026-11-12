package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
)

func awgTestKey(n byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32))
}

func panelAWGTestConfig(version int) string {
	extra := ""
	if version == 31 {
		extra = "HeaderProtectionKey = " + awgTestKey(7) + "\nRandomTrailers = on\nContentPaddingAddition = 5-8\nDisableCookies = on\n"
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.5.%d.2/32\nDNS = 10.5.%d.1\nMTU = 1380\nH1 = 30-35\nH2 = 40-45\nH3 = 50-55\nH4 = 60-65\nS1 = 12\nS2 = 15\nS3 = 12\nS4 = 16\n%s\n# AWG %d\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = node%d.invalid:51820\nPersistentKeepalive = 25\n", awgTestKey(byte(version)), version, version, extra, version, awgTestKey(4), awgTestKey(8), version)
}

func TestAWGPanelSubscriptionRoundTrip(t *testing.T) {
	c, _ := newCtl(t)
	var links []string
	for _, version := range []int{20, 31} {
		cfg := panelAWGTestConfig(version)
		p, err := hysteria.ParseAWGConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, scheme := range []string{"vpn", "amneziawg"} {
			link := scheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(cfg))
			links = append(links, link)
			pp, _, err := hysteria.ParseURI(link)
			if err != nil || !hysteria.SameConnection(pp, p) {
				t.Fatal("formats differ", err)
			}
		}
		add, err := c.ImportURIs(cfg)
		if err != nil || len(add.Added) != 1 || add.Added[0].Protocol != "amneziawg" {
			t.Fatal("manual import", err, add.Errors)
		}
	}
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	subCtl, _ := newCtl(t)
	sub := addSub(t, subCtl, &body)
	report, err := subCtl.SubscriptionDetails(sub.ID)
	if err != nil || len(report.Profiles) != 2 || len(report.Duplicates) != 2 || len(report.Skipped) != 0 {
		t.Fatal("subscription details", err, report)
	}
	saved, err := subCtl.Store.LoadProfiles()
	if err != nil || len(saved.List) != 2 {
		t.Fatal("reload", err)
	}
	for i, p := range saved.List {
		want, _ := hysteria.ParseAWGConfig(panelAWGTestConfig([]int{20, 31}[i]))
		parsed, _, err := hysteria.ParseURI(p.URI())
		if err != nil || !hysteria.SameConnection(parsed, p) || !hysteria.SameConnection(want, p) {
			t.Fatal("saved settings changed", err)
		}
		raw, err := os.ReadFile(filepath.Join(subCtl.Store.Dir, "profiles.json"))
		if err != nil {
			t.Fatal(err)
		}
		summary, _ := json.Marshal(report)
		for _, key := range p.Secrets() {
			if key != "" && (bytes.Contains(raw, []byte(key)) || bytes.Contains(summary, []byte(key))) {
				t.Fatal("AWG credential disclosed")
			}
		}
	}
}

func TestAWGIdentityAndSecretFreeBackup(t *testing.T) {
	p, err := hysteria.ParseAWGConfig(panelAWGTestConfig(31))
	if err != nil {
		t.Fatal(err)
	}
	blank := p
	blank.ClearSecrets()
	if blank.HasSecrets() {
		t.Fatal("backup still has credentials")
	}
	if _, err := validServer(blank, false); err != nil {
		t.Fatal("rejected backup without keys", err)
	}
	for _, key := range p.Secrets() {
		if key != "" && strings.Contains(blank.AWGConfig(), key) {
			t.Fatal("secret in stripped config")
		}
	}
	edited := p
	edited.AWG.PrivateKey = awgTestKey(17)
	if connKey(edited) == connKey(p) || transferKey(edited) == transferKey(p) {
		t.Fatal("same endpoint with different credentials treated as a duplicate")
	}
	edited = p
	edited.Ports = "51821"
	parsed, err := hysteria.ParseAWGConfig(edited.AWGConfig())
	if err != nil || parsed.Ports != edited.Ports {
		t.Fatal("edited endpoint was not applied", err)
	}
	blank.CopySecrets(p)
	if !hysteria.SameConnection(blank, p) {
		t.Fatal("backup lost connection settings")
	}
}

func TestAWGInvalidPanelOptions(t *testing.T) {
	config := panelAWGTestConfig(31)
	for _, bad := range []string{
		strings.Replace(config, "S1 = 12", "S1 = 11", 1),
		strings.Replace(config, "H3 = 50-55", "H3 = 44-55", 1),
		strings.Replace(config, "[Peer]", "PostUp = untrusted instruction\n[Peer]", 1),
		strings.Replace(config, "[Peer]", "Jc = 4-6\n[Peer]", 1),
		strings.Replace(config, "[Peer]", "Jc = 3000000\n[Peer]", 1),
		strings.Replace(config, "[Peer]", "RekeyTimeout = 9-5\n[Peer]", 1),
		config + "[Peer]\nPublicKey = " + awgTestKey(8),
	} {
		res := ParseLinks(bad)
		if len(res.Profiles) != 0 || len(res.Errors) == 0 {
			t.Fatal("accepted an invalid AWG profile")
		}
	}
}
