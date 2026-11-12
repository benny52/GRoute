package app

import (
	"errors"
	"fmt"
	"slices"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

// Plan changes to consumers outside the rules, using the cloned state.
// req.Target for a transfer is resolved against the subscription owner.
func (c *Controller) planRemovalLocked(p *assignmentPlan) error {
	req := &p.req
	n := &p.restore.next
	keep := map[string]bool{}
	if req.Operation == "transfer" {
		old := n.Profiles.Find(req.Source)
		if old == nil || old.Source != "" {
			return errors.New("Ручная копия больше не существует")
		}
		oldKey := transferKey(*old)
		var target *hysteria.Profile
		sources := c.subscriptionSourcesLocked()
		for i := range n.Profiles.List {
			other := &n.Profiles.List[i]
			if sources[other.Source] && (req.Target == "" || other.ID == req.Target) && oldKey == transferKey(*other) {
				if target != nil {
					return errors.New("Есть несколько копий в подписках. Выберите сервер назначения")
				}
				target = other
			}
		}
		if target == nil {
			return errors.New("В подписке больше нет сервера с теми же параметрами подключения")
		}
		req.Target = target.ID
		p.removed[old.ID] = true
		for _, use := range c.serverAssignmentsLocked(old.ID) {
			if use.Indirect {
				use.Detail = "Косвенное назначение сохраняется через основной сервер или группу"
				p.Changes = append(p.Changes, use)
			}
		}
	} else {
		sub := slices.IndexFunc(n.Subs, func(s store.Subscription) bool { return s.ID == req.SubscriptionID })
		if sub < 0 {
			return errors.New("Подписка уже удалена")
		}
		p.change("subscription", n.Subs[sub].Name, "Будет удалена подписка", nil, nil)
		n.Subs = slices.Delete(n.Subs, sub, sub+1)
		p.write("subscriptions.json")
		for _, srv := range n.Profiles.List {
			if srv.Source == "sub:"+req.SubscriptionID {
				p.removed[srv.ID] = true
			}
		}
	}
	// The global target and an explicit rule are independent references.
	if p.removed[n.Profiles.Active] {
		next := ""
		if req.Operation == "transfer" {
			next = req.Target
		}
		label := "Основной сервер"
		if n.Groups.Main != "" {
			label = "Выбранный сервер под основной группой"
		}
		p.change("main", label, "", []string{n.Profiles.Active}, optionalID(next))
		n.Profiles.Active = next
		n.Profiles.AwaitMain = next == ""
		p.write("profiles.json")
	}
	proxies := make([]store.LocalProxy, 0, len(n.Proxies))
	for _, proxy := range n.Proxies {
		if req.Operation == "deleteSubscription" && proxy.Source == "sub:"+req.SubscriptionID {
			p.change("proxy", proxy.Name, "Прокси этой подписки будет удалён", []string{proxy.Profile}, nil)
			p.write("proxies.json")
			continue
		}
		if p.removed[proxy.Profile] {
			if req.Operation == "transfer" {
				p.change("proxy", proxy.Name, "", []string{proxy.Profile}, []string{req.Target})
				proxy.Profile = req.Target
				p.write("proxies.json")
			} else {
				keep[proxy.Profile] = true
				p.change("proxy", proxy.Name, "Удерживает сервер как ручной", []string{proxy.Profile}, []string{proxy.Profile})
			}
		}
		proxies = append(proxies, proxy)
	}
	n.Proxies = proxies
	if req.Operation == "deleteSubscription" {
		// Evaluate every group against the same surviving servers, including
		// independent proxy targets. Results cannot depend on group order.
		var pinned []string
		for i := range n.Groups.Groups {
			g := &n.Groups.Groups[i]
			members := c.membersLocked(g)
			if len(members) == 0 || slices.ContainsFunc(members, func(id string) bool { return !p.removed[id] || keep[id] }) {
				continue
			}
			if c.groupUsedLocked(g.ID) {
				pinned = append(pinned, members...)
			}
		}
		for _, id := range pinned {
			keep[id] = true
		}
	}
	for i := range n.Groups.Groups {
		g := &n.Groups.Groups[i]
		before := slices.Clone(g.Members)
		if req.Operation == "transfer" {
			if !slices.Contains(before, req.Source) {
				continue
			}
			for j, m := range g.Members {
				if m == req.Source {
					g.Members[j] = req.Target
				}
			}
			g.Members = distinctTargets(g.Members, "")
			p.change("group", g.Name, "", before, g.Members)
			p.write("groups.json")
			continue
		}
		follows := slices.Contains(g.Subs, req.SubscriptionID)
		if !follows && !slices.ContainsFunc(before, func(id string) bool { return p.removed[id] }) {
			continue
		}
		previous := c.membersLocked(&c.groupsFile.Groups[i])
		g.Members = slices.DeleteFunc(g.Members, func(id string) bool { return p.removed[id] && !keep[id] })
		if follows {
			g.Subs = slices.DeleteFunc(g.Subs, func(id string) bool { return id == req.SubscriptionID })
			for _, id := range previous {
				if !p.removed[id] || !keep[id] || slices.Contains(g.Members, id) {
					continue
				}
				if len(g.Members) >= groups.MaxMembers {
					return sentencef("Группа «%s» не вместит все серверы подписки как ручные", g.Name)
				}
				g.Members = append(g.Members, id)
			}
		}
		if follows || !slices.Equal(g.Members, before) {
			p.write("groups.json")
		}
		p.change("group", g.Name, "Состав после удаления подписки", previous, c.membersLocked(g))
	}
	if len(p.removed) > 0 {
		list := make([]hysteria.Profile, 0, len(n.Profiles.List))
		for _, srv := range n.Profiles.List {
			if !p.removed[srv.ID] {
				list = append(list, srv)
				continue
			}
			if keep[srv.ID] {
				srv.Source = ""
				srv.Missing = false
				list = append(list, srv)
				p.change("server", srv.Name, "Останется ручным для группы или локального прокси", []string{srv.ID}, []string{srv.ID})
			} else if req.Operation == "transfer" {
				p.change("server", srv.Name, "Назначения будут перенесены, ручная копия удалена", []string{srv.ID}, []string{req.Target})
			} else {
				p.change("server", srv.Name, "Будет удалён", []string{srv.ID}, nil)
			}
		}
		n.Profiles.List = list
		p.write("profiles.json")
	}
	return nil
}
func optionalID(id string) []string {
	if id == "" {
		return []string{}
	}
	return []string{id}
}

// ServerAssignments includes disabled rules and saved profiles; indirect
// membership and inheritance are useful for explaining an apparent pin.
func (c *Controller) ServerAssignments(id string) ([]AssignmentChange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.profiles.Find(id) == nil {
		return nil, errors.New("Сервер не найден")
	}
	if err := c.refsUnknownLocked(); err != nil {
		return nil, err
	}
	if c.groupsBroken != nil {
		return nil, c.groupsBroken
	}
	if c.rulesets != nil {
		for _, rs := range c.rulesets.List {
			if rs.Newer() {
				return nil, sentencef("Профиль «%s» создан более новой версией. Невозможно проверить все назначения", rs.Name)
			}
		}
	}
	return c.serverAssignmentsLocked(id), nil
}

func (c *Controller) serverAssignmentsLocked(id string) []AssignmentChange {
	out := []AssignmentChange{}
	add := func(ch AssignmentChange, target string) {
		resolved := target
		if resolved == "" {
			resolved = c.mainTargetLocked()
		}
		match := resolved == id
		if g := c.groupLocked(resolved); g != nil {
			match = c.groupHasLocked(g, id)
		}
		if match {
			ch.Indirect = target == "" || resolved != id
			out = append(out, ch)
		}
	}
	c.eachRulesConfigLocked(func(label string, active bool, cfg *rules.Config) {
		if active {
			label = c.activeRulesetNameLocked()
			if label == "" {
				label = defaultRulesetName
			}
		}
		route := func(kind, name string, off bool, primary string, fb []string) {
			ch := AssignmentChange{Kind: kind, RulesetName: label, Name: name, Disabled: off, Role: "primary"}
			add(ch, primary)
			ch.Role = "fallback"
			for i, tid := range fb {
				ch.Position = i + 1
				add(ch, tid)
			}
		}
		for i, r := range cfg.Rules {
			if r.Action != rules.Tunnel {
				continue
			}
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("Правило %d", i+1)
			}
			route("rule", name, r.Enabled != nil && !*r.Enabled, r.Profile, r.Fallback)
		}
		if cfg.DefaultAction == rules.Tunnel {
			route("default", "Всё остальное", false, cfg.DefaultProfile, cfg.DefaultFallback)
		}
	})
	if main := c.mainTargetLocked(); main != "" {
		add(AssignmentChange{Kind: "main", Name: "Основной сервер"}, main)
	}
	if c.groupsFile.Main != "" && c.profiles.Active == id {
		out = append(out, AssignmentChange{Kind: "main", Name: "Выбранный сервер под основной группой"})
	}
	for _, g := range c.groupsFile.Groups {
		if c.groupHasLocked(&g, id) {
			out = append(out, AssignmentChange{Kind: "group", Name: g.Name, Indirect: !slices.Contains(g.Members, id)})
		}
	}
	for _, proxy := range c.proxies {
		add(AssignmentChange{Kind: "proxy", Name: proxy.Name, Disabled: !proxy.Enabled}, proxy.Profile)
	}
	return out
}
