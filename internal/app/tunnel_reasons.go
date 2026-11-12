package app

import (
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
)

// TunnelReason describes one assignment that needs a running server. Group
// names and counts come from the configuration applied to the same session.
type TunnelReason struct {
	Role    string `json:"role"` // primary, main, fallback, main-fallback, proxy
	Count   int    `json:"count"`
	Default bool   `json:"default,omitempty"` // «Всё остальное» is separate from rules
	Group   string `json:"group,omitempty"`   // the target was this group
}

func (c *Controller) tunnelReasonsLocked(main string, want []hysteria.Profile, usedGroups []string) map[string][]TunnelReason {
	targets := make(map[string][]TunnelReason)
	add := func(id, role string, def bool) {
		if id == "" {
			return
		}
		for i, reason := range targets[id] {
			if reason.Role == role && reason.Default == def {
				targets[id][i].Count++
				return
			}
		}
		targets[id] = append(targets[id], TunnelReason{Role: role, Count: 1, Default: def})
	}
	route := func(primary string, fallbacks []string, def bool) {
		role := "primary"
		if primary == "" {
			primary, role = main, "main"
		}
		add(primary, role, def)
		seen := map[string]bool{primary: true}
		for _, id := range fallbacks {
			role := "fallback"
			if id == "" {
				id, role = main, "main-fallback"
			}
			if !seen[id] {
				add(id, role, def)
				seen[id] = true
			}
		}
	}
	for _, r := range c.settings.Rules {
		if r.Action == rules.Tunnel && (r.Enabled == nil || *r.Enabled) {
			route(r.Profile, r.Fallback, false)
		}
	}
	if c.settings.DefaultAction == rules.Tunnel {
		route(c.settings.DefaultProfile, c.settings.DefaultFallback, true)
	}
	// A proxy targeting a group eagerly starts that group's members.
	// Direct proxy demand changes independently of rule application.
	proxyTargets := make(map[string]bool)
	for _, p := range c.proxies {
		id := c.proxyProfileLocked(p)
		if p.Enabled && groups.IsGroupID(id) && !proxyTargets[id] {
			add(id, "proxy", false)
			proxyTargets[id] = true
		}
	}
	out := make(map[string][]TunnelReason, len(want))
	for _, p := range want {
		out[p.ID] = targets[p.ID]
	}
	for _, id := range usedGroups {
		g := c.groupLocked(id)
		for _, member := range c.runMembersLocked(g) {
			for _, reason := range targets[id] {
				reason.Group = g.Name
				out[member] = append(out[member], reason)
			}
		}
	}
	return out
}

// An enabled direct proxy needs the target only while it is awake. Several
// listeners can share that target's open connections and idle window.
func (c *Controller) awakeProxyTargetsLocked() map[string]bool {
	if len(c.proxyAwake) == 0 {
		return nil
	}
	awake := make(map[string]bool)
	for _, p := range c.proxies {
		id := c.proxyProfileLocked(p)
		if p.Enabled && c.proxyAwake[id] != nil {
			awake[id] = true
		}
	}
	return awake
}
