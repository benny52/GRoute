package app

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

func TestAssignmentsDeleteSUB1(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://demo@one.example:443#server1\nhy2://demo@two.example:443#server2\nhy2://demo@three.example:443#server3"
	sub := addSub(t, c, &body)
	p := c.Profiles()
	st := c.Settings()
	st.Rules = []rules.Rule{
		{Name: "LAN", Domains: []string{"home.example"}, Action: rules.Direct},
		{Name: "YouTube", Domains: []string{"video.example"}, Action: rules.Tunnel, Profile: p[0].ID, Fallback: []string{p[2].ID}},
		{Name: "Telegram", Domains: []string{"chat.example"}, Action: rules.Tunnel, Profile: p[1].ID, Fallback: []string{p[2].ID}},
	}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	req := AssignmentRequest{Operation: "deleteSubscription", SubscriptionID: sub.ID}
	preview, err := c.PreviewAssignments(req)
	if err != nil || len(preview.Changes) < 5 {
		t.Fatal(preview, err)
	}
	if len(c.Profiles()) != 3 {
		t.Fatal("preview wrote servers")
	}
	c.restoreWriteHook = func(f string) error {
		if f == "settings.json" {
			return errors.New("simulated failure")
		}
		return nil
	}
	if err = c.ApplyAssignments(req, preview.Token); err == nil {
		t.Fatal("wanted write failure")
	}
	if len(c.Profiles()) != 3 || len(c.Subscriptions()) != 1 {
		t.Fatal("partial update")
	}
	c.restoreWriteHook = nil
	if err = c.ApplyAssignments(req, preview.Token); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := newCtlAt(t, c.Store)
	if len(reloaded.Profiles()) != 0 || len(reloaded.Subscriptions()) != 0 {
		t.Fatal("servers retained")
	}
	got := reloaded.Settings().Rules
	if len(got) != 3 || got[0].Action != rules.Direct {
		t.Fatal(got)
	}
	for _, r := range got[1:] {
		if r.Action != rules.Tunnel || r.Profile != "" || len(r.Fallback) != 0 {
			t.Fatal(r)
		}
	}
	added, err := reloaded.ImportURIs("hy2://test@four.example#Fourth")
	if err != nil || len(added.Added) != 1 {
		t.Fatal(err)
	}
	if reloaded.Status().MainID != "" {
		t.Fatal("import implicitly selected main after deletion")
	}
	if err = reloaded.SetMain(added.Added[0].ID); err != nil {
		t.Fatal(err)
	}
	if reloaded.Status().MainID != added.Added[0].ID || reloaded.Settings().Rules[1].Profile != "" {
		t.Fatal("inheritance lost")
	}
}

func TestAssignmentsLegacyDuplicateID(t *testing.T) {
	c, _ := newCtl(t)
	a, b, _ := servers(t, c)
	r := curlRule(a)
	r.ID = "duplicate"
	setRules(t, c, rules.Direct, "", r, r)
	req := AssignmentRequest{Operation: "set", Role: "primary", Target: b, Rows: []AssignmentRow{{RuleID: r.ID}}}
	if _, err := c.PreviewAssignments(req); err == nil {
		t.Fatal("accepted ambiguous ID")
	}
	second := 1
	req.Rows[0].Index = &second
	req.Rows[0].Revision = fmt.Sprintf("%d/0", c.SettingsRev())
	v, err := c.PreviewAssignments(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyAssignments(req, v.Token); err != nil {
		t.Fatal(err)
	}
	got := c.Settings().Rules
	if got[0].Profile != a || got[1].Profile != b {
		t.Fatal("wrong row changed")
	}
}

func TestAssignmentsSelectedRoles(t *testing.T) {
	c, _ := newCtl(t)
	added, err := c.ImportURIs("hy2://a@one.example#A\nhy2://b@two.example#B\nhy2://c@three.example#C")
	if err != nil {
		t.Fatal(err)
	}
	a, b, d := added.Added[0].ID, added.Added[1].ID, added.Added[2].ID
	st := c.Settings()
	st.Rules = []rules.Rule{{ID: "r1", Name: "Video", Domains: []string{"video.example"}, Action: rules.Tunnel, Profile: a, Fallback: []string{d}}}
	if _, err = c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	req := AssignmentRequest{Operation: "set", Role: "primary", Target: b, Rows: []AssignmentRow{{RuleID: "r1"}}}
	v, err := c.PreviewAssignments(req)
	if err != nil || len(v.Changes) != 1 {
		t.Fatal(v, err)
	}
	if err = c.SetMain(d); err != nil {
		t.Fatal(err)
	}
	if err = c.ApplyAssignments(req, v.Token); err == nil {
		t.Fatal("accepted stale plan")
	}
	v, err = c.PreviewAssignments(req)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ApplyAssignments(req, v.Token); err != nil {
		t.Fatal(err)
	}
	r := c.Settings().Rules[0]
	if r.Profile != b || !slices.Equal(r.Fallback, []string{d}) {
		t.Fatal(r)
	}
	v, err = c.PreviewAssignments(req)
	if err != nil || len(v.Changes) != 0 {
		t.Fatal(v, err)
	}
}
