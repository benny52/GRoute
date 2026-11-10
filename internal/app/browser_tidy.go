package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/rules"
)

// «Навести порядок» for the extension's rules by route (browser.go): the
// ones it made before it kept a rule per site, and what became of them
// since. A server renamed in its subscription leaves «Из браузера: <old
// name>» beside «Из браузера: <new name>» with the same route; a list or
// a network added by hand makes the rule one the extension no longer
// keeps, and it starts another of the same name; an earlier merge left
// names like «Из браузера: напрямую, Локальная сеть». One suggestion
// puts them right: a rule per route, named after the route as it is called
// now, holding plain sites only (so the extension keeps it again), what is
// not a plain site in a rule of its own. A site's rule a list was added to
// is split the same way, under its own name. Which page a site was sent from
// was never recorded, so these cannot be split by site; a site sent again
// from its page moves into that site's rule (BrowserAdd).

// TidyBrowser is the suggestion's ID and kind.
const TidyBrowser = "browser"

// browserSpareSuffix ends the name of a rule by route the user gave spare
// servers: another route than the plain one's, under a name of its own.
const browserSpareSuffix = " (с запасными)"

// browserNamed: r reads as a rule of the extension, kept by it or not any
// more: named «Из браузера: …», enabled, destinations only.
func browserNamed(r rules.Rule) bool {
	return strings.HasPrefix(r.Name, BrowserRulePrefix) && r.On() && len(r.AllApps()) == 0 && len(r.Ports) == 0 &&
		(r.Protocol == "" || strings.EqualFold(r.Protocol, "any"))
}

// browserPlain: such a rule with plain sites only.
func browserPlain(r rules.Rule) bool {
	if !browserNamed(r) || len(r.AllDomains()) == 0 {
		return false
	}
	for _, d := range r.AllDomains() {
		if _, ok := browserPattern(d); !ok {
			return false
		}
	}
	return true
}

// browserWord is the route of r as the extension names it now ("" = a
// server that is gone: the rule keeps its name).
func (c *Controller) browserWord(r rules.Rule) string {
	switch r.Action {
	case rules.Direct:
		return "напрямую"
	case rules.Block:
		return "блок"
	}
	if r.Profile == "" {
		return "VPN"
	}
	c.mu.Lock()
	ts := c.targetsLocked()
	c.mu.Unlock()
	if slices.ContainsFunc(ts, func(t target) bool { return t.ID == r.Profile }) {
		return c.profileName(r.Profile)
	}
	return ""
}

// browserRest is what a name merged with others' holds besides the
// extension's («Из браузера: напрямую, Локальная сеть» → «Локальная сеть»).
func browserRest(name string) string {
	var out []string
	for _, p := range strings.Split(name, ", ") {
		if p = strings.TrimSpace(p); p != "" && !strings.HasPrefix(p, BrowserRulePrefix) {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

func sameBrowserRoute(a, b rules.Rule) bool {
	return a.Action == b.Action && a.Profile == b.Profile && slices.Equal(a.Fallback, b.Fallback) &&
		browserHostsRule(a) == browserHostsRule(b)
}

// browserTidy puts the rules by route in order and says what it did, a
// line per change (none: nothing to do). A rule's sites join an earlier
// rule only when no rule between decides any of them another way for
// everyone (rules.CanMoveUp), otherwise the rule stays where it is under
// its right name. changes: a program's rule stood between (the DPI
// bypass's «Discord (голос)»): for that program the sites go the joined
// rule's way now, and a line says so.
func (c *Controller) browserTidy(cfg rules.Config, o rules.TidyOptions) (res rules.Config, details []string, changes bool) {
	out := cfg
	out.Rules = make([]rules.Rule, 0, len(cfg.Rules))
	q := func(s string) string {
		if s == "" {
			return "правило без названия"
		}
		return "правило «" + s + "»"
	}
	// 1. Each rule in its place: plain sites under the route's name, the
	// rest in a rule of its own right below.
	for _, r := range cfg.Rules {
		r = r.Clone()
		if !browserNamed(r) {
			out.Rules = append(out.Rules, r)
			continue
		}
		var plain, other []string
		for _, d := range r.AllDomains() {
			if p, ok := browserPattern(d); ok {
				if !slices.Contains(plain, p) {
					plain = append(plain, p)
				}
			} else {
				other = append(other, d)
			}
		}
		// A site's rule keeps its name; a rule by route is named after the
		// route.
		old, name := r.Name, r.Name
		if w := c.browserWord(r); w != "" && browserRuleSite(r) == "" {
			name = BrowserRulePrefix + w
			if len(r.Fallback) > 0 {
				// Not the extension's any more (it keeps no spare servers),
				// and not the rule of that name without them.
				name += browserSpareSuffix
			}
			if browserHostsRule(r) {
				name += browserHostsSuffix
			}
		}
		rest := r.Clone()
		rest.Name, rest.Domains, rest.Domain = browserRest(old), other, nil
		switch {
		case len(plain) == 0 && len(other) == 0:
			out.Rules = append(out.Rules, r)
		case len(plain) == 0:
			// Lists and networks only: not the extension's any more.
			if rest.Name == "" {
				details = append(details, fmt.Sprintf("«%s» остаётся без названия: в нём только списки и сети, расширение его не ведёт.", old))
			} else {
				details = append(details, fmt.Sprintf("«%s» переименовано в «%s»: в нём только списки и сети, расширение его не ведёт.", old, rest.Name))
			}
			out.Rules = append(out.Rules, rest)
		default:
			r.Name, r.Domains, r.Domain = name, plain, nil
			out.Rules = append(out.Rules, r)
			if len(other) > 0 {
				rest.ID = newID()
				line := fmt.Sprintf("«%s»: %s — в отдельное %s сразу под ним; сайты остаются в «%s»", old, itemsText(other), q(rest.Name), name)
				if isBrowserRule(r) {
					line += ", и расширение снова может его вести"
				}
				details = append(details, line+".")
				out.Rules = append(out.Rules, rest)
			} else if name != old {
				details = append(details, fmt.Sprintf("«%s» переименовано в «%s»: так этот маршрут называется сейчас.", old, name))
			}
		}
	}
	// 2. One rule per route: later ones join the first that they can
	// reach.
	for base := 0; base < len(out.Rules); base++ {
		b := out.Rules[base]
		if !browserPlain(b) {
			continue
		}
		joined := 0
		var between []string
		for j := base + 1; j < len(out.Rules); j++ {
			r := out.Rules[j]
			if !browserPlain(r) || r.Name != b.Name || !sameBrowserRoute(b, r) {
				continue
			}
			ok, soft := rules.CanMoveUp(out, o, base, j)
			if !ok {
				continue
			}
			for _, n := range soft {
				if !slices.Contains(between, n) {
					between = append(between, n)
				}
			}
			for _, d := range r.Domains {
				if !slices.Contains(out.Rules[base].Domains, d) {
					out.Rules[base].Domains = append(out.Rules[base].Domains, d)
				}
			}
			out.Rules = slices.Delete(out.Rules, j, j+1)
			j--
			joined++
		}
		if joined > 0 {
			n := len(out.Rules[base].Domains)
			line := fmt.Sprintf("«%s»: %s с этим маршрутом собраны в одно (%s).", b.Name,
				plural(joined+1, "правило", "правила", "правил"), plural(n, "сайт", "сайта", "сайтов"))
			if len(between) > 0 {
				changes = true
				line += " Между ними стоит «" + strings.Join(between, "», «") + "»: для его программ эти сайты пойдут так же, как для остальных."
			}
			details = append(details, line)
		}
	}
	if len(details) == 0 {
		return cfg, nil, false
	}
	return out, details, changes
}

func itemsText(s []string) string {
	if len(s) <= 3 {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s, %s и ещё %d", s[0], s[1], len(s)-2)
}
