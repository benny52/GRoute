package app

import (
	"errors"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

func TestAssignmentEditorAcrossProfiles(t *testing.T) {
	c, _ := newCtl(t)
	a, b, d := servers(t, c)
	r := curlRule(a, b)
	r.ID = "active-rule"
	setRules(t, c, rules.Direct, "", r)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: b, DefaultFallback: []string{d}})
	req := AssignmentRequest{Operation: "edit", Edits: []AssignmentEdit{
		{Row: AssignmentRow{RulesetID: home, RuleID: r.ID}, BeforePrimary: a, BeforeFallback: []string{b}, Primary: d, Fallback: []string{b, a}},
		{Row: AssignmentRow{RulesetID: work, IsDefault: true}, BeforePrimary: b, BeforeFallback: []string{d}, Primary: "", Fallback: []string{a, d}},
	}}
	v, err := c.PreviewAssignments(req)
	if err != nil || len(v.Changes) != 4 {
		t.Fatal(v, err)
	}
	if c.Settings().Rules[0].Profile != a {
		t.Fatal("preview mutated active rule")
	}
	req.Edits[1].BeforeFallback = nil
	if err := c.ApplyAssignments(req, v.Token); !errors.Is(err, ErrPlanChanged) {
		t.Fatal("stale row", err)
	}
	if c.Settings().Rules[0].Profile != a {
		t.Fatal("partial edit")
	}
	req.Edits[1].BeforeFallback = []string{d}
	if err := c.ApplyAssignments(req, v.Token); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := newCtlAt(t, c.Store)
	got := reloaded.Settings().Rules[0]
	if got.Profile != d || !slices.Equal(got.Fallback, []string{b, a}) {
		t.Fatal(got)
	}
	saved, err := reloaded.RulesetSettings(work)
	if err != nil || saved.Config.DefaultProfile != "" || !slices.Equal(saved.Config.DefaultFallback, []string{a, d}) {
		t.Fatal(saved, err)
	}
}

func TestAssignmentDeleteSingleMain(t *testing.T) {
	c, _ := newCtl(t)
	body := threeServers
	_ = addSub(t, c, &body)
	profiles := c.Profiles()
	a, b, d := profiles[0].ID, profiles[1].ID, profiles[2].ID
	if err := c.SetMain(a); err != nil {
		t.Fatal(err)
	}
	setRules(t, c, rules.Direct, "", curlRule(a, d))
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: b, DefaultFallback: []string{a, d}})
	req := AssignmentRequest{Operation: "deleteServer", Source: a}
	v, err := c.PreviewAssignments(req)
	if err != nil || len(v.Warnings) == 0 || c.Status().MainID != a || len(c.Profiles()) != 3 {
		t.Fatal(v, err)
	}
	if err := c.ApplyAssignments(req, v.Token); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := newCtlAt(t, c.Store)
	if len(reloaded.Subscriptions()) != 1 || len(reloaded.Profiles()) != 2 || reloaded.Status().MainID != "" {
		t.Fatal("incorrect main, subscription or server count")
	}
	got := reloaded.Settings().Rules[0]
	if got.Action != rules.Tunnel || got.Profile != "" || !slices.Equal(got.Fallback, []string{d}) {
		t.Fatal(got)
	}
	saved, err := reloaded.RulesetSettings(work)
	if err != nil || saved.Config.DefaultProfile != b || !slices.Equal(saved.Config.DefaultFallback, []string{d}) {
		t.Fatal(saved, err)
	}
}
