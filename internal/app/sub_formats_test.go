package app

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

// 3x-ui serves each Xray node separately, then repeats its outbounds in a
// balancer. Serve five VLESS and two Hysteria 2 nodes in all three formats.
func TestSubscriptionFormatsKeepRuleTargets(t *testing.T) {
	const uuid = "c3ceb14d-4992-4776-b750-7978ab8591c1"
	vless := `{"tag":"proxy","protocol":"vless","settings":{"address":"v.example","port":443,"id":"` + uuid + `","encryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"v.example"}}}`
	hy := func(host string) string {
		return fmt.Sprintf(`{"tag":"proxy","protocol":"hysteria","settings":{"version":2,"address":%q,"port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"tls.example","alpn":["h2","http/1.1"]},"hysteriaSettings":{"version":2,"auth":"demo"}}}`, host)
	}
	outbounds := []string{hy("a.example"), hy("b.example")}
	clash := "proxies:\n  - {name: A, type: hysteria2, server: a.example, port: 443, password: demo, sni: tls.example}\n  - {name: B, type: hysteria2, server: b.example, port: 443, password: demo, sni: tls.example}\n"
	plain := "hysteria2://demo@a.example:443?sni=tls.example#A\nhy2://demo@b.example:443?sni=tls.example#B"
	for i := 1; i <= 5; i++ {
		host := fmt.Sprintf("v%d.example", i)
		outbounds = append(outbounds, strings.ReplaceAll(vless, "v.example", host))
		plain += fmt.Sprintf("\nvless://%s@%s:443?security=tls&sni=%s#V%d", uuid, host, host, i)
		clash += fmt.Sprintf("  - {name: V%d, type: vless, server: %s, port: 443, uuid: %s, tls: true, servername: %s}\n", i, host, uuid, host)
	}
	plain += "\nvpn://" + base64.RawURLEncoding.EncodeToString([]byte("[Interface]\nPrivateKey=example\nJc=2\n[Peer]\nPublicKey=example"))
	var singles, balanced []string
	for i, ob := range outbounds {
		singles = append(singles, fmt.Sprintf(`{"remarks":"Example %d","outbounds":[%s]}`, i, ob))
		balanced = append(balanced, strings.Replace(ob, `"tag":"proxy"`, fmt.Sprintf(`"tag":"bal-1-%d"`, i), 1))
	}
	singles = append(singles, `{"outbounds":[`+strings.Join(balanced, ",")+`]}`)
	xray := "[" + strings.Join(singles, ",") + "]"
	c, _ := newCtl(t)
	mux := http.NewServeMux()
	for path, body := range map[string]string{"/custom/": base64.StdEncoding.EncodeToString([]byte(plain)), "/jsonurl/": xray, "/clash/": clash} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
	}
	panel := httptest.NewServer(mux)
	t.Cleanup(panel.Close)
	start, err := c.PreviewSubscription(panel.URL + "/custom/")
	if err != nil || !start.Base64 || len(start.Report.Skipped) != 1 || start.Report.Skipped[0].Protocol != "AmneziaWG" {
		t.Fatalf("plain preview: base64=%v, err=%v", start.Base64, err)
	}
	sub, err := c.AddSubscription(SubInput{Token: start.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	original := c.Profiles()
	if len(original) != 7 {
		t.Fatalf("plain subscription: got %d servers", len(original))
	}
	priority, backup := original[0].ID, original[1].ID
	setRules(t, c, rules.Direct, "", curlRule(priority, backup))
	for _, tc := range []struct {
		format, path string
		duplicates   int
	}{{"Xray", "/jsonurl/", 7}, {"Clash", "/clash/", 0}} {
		pv, err := c.PreviewSubscription(panel.URL + tc.path)
		if err != nil || pv.Format != tc.format || len(pv.Report.Profiles) != 7 || len(pv.Report.Duplicates) != tc.duplicates || len(pv.Report.Skipped) != 0 {
			t.Fatalf("%s preview: %d unique, %d duplicates, %d skipped, err %v", tc.format, len(pv.Report.Profiles), len(pv.Report.Duplicates), len(pv.Report.Skipped), err)
		}
		counts := map[string]int{}
		for _, node := range pv.Report.Profiles {
			counts[node.Protocol]++
		}
		if counts["VLESS"] != 5 || counts["Hysteria 2"] != 2 || len(pv.Report.Warnings) != 0 {
			t.Fatalf("%s unexpected protocols or warnings: %v, %v", tc.format, counts, pv.Report.Warnings)
		}
		if err = c.EditSubscription(SubInput{ID: sub.ID, Token: pv.Token, Enabled: true, Interval: "manual"}); err != nil {
			t.Fatal(err)
		}
		if _, err = c.UpdateSubscription(sub.ID); err != nil {
			t.Fatal(err)
		}
		reloaded, _ := newCtlAt(t, c.Store)
		report, err := reloaded.SubscriptionDetails(sub.ID)
		if err != nil || len(report.Profiles) != 7 || len(report.Duplicates) != tc.duplicates {
			t.Fatalf("%s saved report mismatches preview", tc.format)
		}
		got := reloaded.Settings().Rules[0]
		if got.Profile != priority || !slices.Equal(got.Fallback, []string{backup}) {
			t.Fatalf("%s changed rule assignments", tc.format)
		}
		for _, id := range []string{priority, backup} {
			p := reloaded.profiles.Find(id)
			if p == nil || p.Missing || p.IsVLESS() || p.Auth != "demo" || p.TLS.SNI != "tls.example" {
				t.Fatalf("%s did not preserve Hysteria 2 credentials and identity", tc.format)
			}
		}
	}
}
