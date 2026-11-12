package app

import (
	"errors"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

func TestAssignmentPreviewWithUnknownReferences(t *testing.T) {
	c, _ := newCtl(t)
	a, _, _ := servers(t, c)
	body := "hy2://a@de1.example:443#DE1"
	addSub(t, c, &body)
	c.mu.Lock()
	c.subs = nil // The subscription file was saved but an older client left its servers.
	c.mu.Unlock()
	if _, err := c.PreviewAssignments(AssignmentRequest{Operation: "transfer", Source: a}); err == nil {
		t.Fatal("accepted orphan as replacement")
	}
	c.mu.Lock()
	c.rulesets = rsNewerFixture(t)
	c.mu.Unlock()
	if _, err := c.ServerAssignments(a); err == nil {
		t.Fatal("reported complete usage of unknown rule fields")
	}
}

func TestAssignmentTransferAcrossConsumers(t *testing.T) {
	c, _ := newCtl(t)
	a, b, d := servers(t, c)
	body := "hy2://a@de1.example:443#DE1"
	addSub(t, c, &body)
	var twin string
	for _, p := range c.Profiles() {
		if p.ID == a {
			twin = p.DuplicateID
		}
	}
	if twin == "" {
		t.Fatal("no subscription copy")
	}
	setRules(t, c, rules.Direct, "", curlRule(a), curlRule(""))
	off := false
	r := curlRule(d, b, a)
	r.Enabled = &off
	cfg := rules.Config{Rules: []rules.Rule{r}, DefaultAction: rules.Tunnel, DefaultProfile: a}
	other := rsCreate(t, c, RulesetInput{Name: "Дом", FirstName: "Работа", Config: &cfg}).View.ID
	g := saveGroup(t, c, "Группа", groups.Failover, b, a, d)
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "Proxy", Port: 17991, Profile: a}}); err != nil {
		t.Fatal(err)
	}
	usage, err := c.ServerAssignments(a)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(usage, func(x AssignmentChange) bool { return x.RulesetName == "Дом" && x.Disabled && x.Position == 2 }) {
		t.Fatal(usage)
	}
	req := AssignmentRequest{Operation: "transfer", Source: a, Target: twin}
	v, err := c.PreviewAssignments(req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(v.Changes, func(ch AssignmentChange) bool { return ch.Kind == "rule" && ch.Indirect && ch.Detail != "" }) {
		t.Fatal("missing inherited rule in transfer preview")
	}
	files := []string{"profiles.json", "groups.json", "proxies.json", "settings.json", "rulesets.json"}
	before := map[string]string{}
	for _, name := range files {
		before[name] = string(fileBytes(t, c, name))
	}
	for _, f := range files {
		// A settings/rulesets pair is committed through WriteRulesPair.
		if f == "rulesets.json" {
			continue
		}
		c.restoreWriteHook = func(name string) error {
			if name == f {
				return errors.New("write failed")
			}
			return nil
		}
		if err = c.ApplyAssignments(req, v.Token); err == nil {
			t.Fatalf("wanted failure: %s", f)
		}
		for _, name := range files {
			if string(fileBytes(t, c, name)) != before[name] {
				t.Fatalf("%s after error at %s", name, f)
			}
		}
	}
	c.restoreWriteHook = nil
	if err = c.ApplyAssignments(req, v.Token); err != nil {
		t.Fatal(err)
	}
	fresh, _ := newCtlAt(t, c.Store)
	if fresh.profiles.Find(a) != nil || fresh.profiles.Active != twin || fresh.settings.Rules[0].Profile != twin || fresh.settings.Rules[1].Profile != "" {
		t.Fatal("main or active rules lost")
	}
	rr := fresh.rulesets.Find(other).Config
	if rr.DefaultProfile != twin || !slices.Equal(rr.Rules[0].Fallback, []string{b, twin}) || *rr.Rules[0].Enabled {
		t.Fatal(rr)
	}
	if !slices.Equal(fresh.groupsFile.Find(g).Members, []string{b, twin, d}) || fresh.proxies[0].Profile != twin {
		t.Fatal("group or proxy did not move")
	}
	// Local TLS settings absent from a share link must still distinguish endpoints.
	profile := *fresh.profiles.Find(twin)
	different := profile
	different.TLS.CA = "different-test-ca"
	if transferKey(profile) == transferKey(different) {
		t.Fatal("CA omitted from identity")
	}
}
