package rules

import (
	"fmt"
	"slices"
	"strings"
)

// Tidying («Навести порядок»): suggestions that bring a long, grown rule
// list in order. Each is applied only when the user ticks it. drop, sites
// and merge never change where a connection goes (merge says so when it
// would: Changes); geo does: a geosite category brings the rest of a
// service's addresses.

const (
	TidyDrop  = "drop"  // a rule that never matches or repeats one above
	TidySites = "sites" // sites a rule never gets or has twice
	TidyMerge = "merge" // rules with the same route, one after another
	TidyGeo   = "geo"   // sites of a service → its geosite category
)

// Tidy is one suggestion.
type Tidy struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Title string `json:"title"`
	// Details: one line per site, rule or consequence.
	Details []string `json:"details"`
	// Rules: the IDs of the rules it changes; for merge the first is the
	// one that stays.
	Rules []string `json:"rules"`
	// Sites: removed (sites) or replaced (geo) items, as written.
	Sites    []string `json:"sites,omitempty"`
	Category string   `json:"category,omitempty"` // geo: "geosite:youtube"
	Name     string   `json:"name,omitempty"`     // merge: the merged rule's name
	// Changes: applying it changes where some connections go.
	Changes bool `json:"changes"`
}

// SiteCategory is a geosite category containing a name.
type SiteCategory struct {
	Name       string
	Size       int
	Subdomains bool // every name under it is in the category too
}

// TidyOptions are what the rules alone do not know.
type TidyOptions struct {
	// Managed: rules HyRoute keeps itself (the DPI bypass): never changed,
	// and not counted as catching anything, since they come and go.
	Managed func(Rule) bool
	// Categories finds the geosite categories of names, the ones worth
	// suggesting only (not regions or registries). nil: no geo
	// suggestions.
	Categories func(names []string) (map[string][]SiteCategory, error)
	// Route names a server or group ID ("" = the main one).
	Route func(id string) string
}

// TidyResult is the list of suggestions.
type TidyResult struct {
	Items []Tidy `json:"items"`
	// GeoNote: why there are no geosite suggestions ("" = looked).
	GeoNote string `json:"geoNote,omitempty"`
}

type tidyRow struct {
	r       Rule
	cr      compiled
	id      string
	use     bool // enabled, compiles, not managed
	dropped bool // a drop suggestion: matches nothing
}

func tidyRows(c Config, o TidyOptions) []tidyRow {
	g := currentGeo()
	rows := make([]tidyRow, len(c.Rules))
	for i, r := range c.Rules {
		rows[i] = tidyRow{r: r, id: tidyID(i, r)}
		cr, err := compileRule(i, r, g)
		if err != nil || !r.On() || o.Managed != nil && o.Managed(r) {
			continue
		}
		rows[i].cr, rows[i].use = cr, true
	}
	return rows
}

// tidyID: a rule without an ID (settings from before IDs) is named by its
// place; ApplyTidy strips such names again.
func tidyID(i int, r Rule) string {
	if r.ID != "" {
		return r.ID
	}
	return fmt.Sprintf("#%d", i)
}

func sameRuleRoute(a, b *compiled) bool {
	return a.action == b.action && (a.action != Tunnel || a.profile == b.profile) && slices.Equal(a.fallback, b.fallback)
}

func routeText(cr *compiled, o TidyOptions) string {
	switch cr.action {
	case Direct:
		return "напрямую"
	case Block:
		return "блокировка"
	}
	if o.Route != nil {
		if n := o.Route(cr.profile); n != "" {
			return "через «" + n + "»"
		}
	}
	return "через VPN"
}

// TidyRules lists the suggestions for c.
func TidyRules(c Config, o TidyOptions) TidyResult {
	rows := tidyRows(c, o)
	res := TidyResult{Items: []Tidy{}}
	res.Items = append(res.Items, tidyDrops(rows, o)...)
	res.Items = append(res.Items, tidySites(rows, o)...)
	res.Items = append(res.Items, tidyMerges(rows, o)...)
	geo, note := tidyGeo(rows, o)
	res.Items = append(res.Items, geo...)
	res.GeoNote = note
	return res
}

// tidyDrops: rules an earlier rule catches every connection of.
func tidyDrops(rows []tidyRow, o TidyOptions) []Tidy {
	var out []Tidy
	for j := range rows {
		if !rows[j].use {
			continue
		}
		for i := range j {
			if !rows[i].use || rows[i].dropped || !rows[i].cr.covers(&rows[j].cr) {
				continue
			}
			t := Tidy{ID: "drop:" + rows[j].id, Kind: TidyDrop, Rules: []string{rows[j].id},
				Title: "Удалить правило «" + rows[j].cr.name + "»"}
			if sameRuleRoute(&rows[i].cr, &rows[j].cr) {
				t.Details = []string{"Повторяет правило «" + rows[i].cr.name + "» выше: всё, что оно ловит, уже идёт туда же."}
			} else {
				t.Details = []string{"Никогда не срабатывает: все его соединения раньше забирает правило «" + rows[i].cr.name + "» (" + routeText(&rows[i].cr, o) + ")."}
			}
			if usesGeo(&rows[i].cr) {
				t.Changes = true
				t.Details = append(t.Details, geoDepends)
			}
			rows[j].dropped = true
			out = append(out, t)
			break
		}
	}
	return out
}

// single is rule r with only its destination item d.
func single(i int, r Rule, d string) (compiled, bool) {
	r.Domains, r.Domain = []string{d}, nil
	cr, err := compileRule(i, r, currentGeo())
	return cr, err == nil
}

// tidySites: sites of a rule that an earlier rule always gets first, or
// that another site of the same rule already covers.
func tidySites(rows []tidyRow, o TidyOptions) []Tidy {
	var out []Tidy
	for j := range rows {
		if !rows[j].use || rows[j].dropped {
			continue
		}
		items := rows[j].r.AllDomains()
		if len(items) < 1 {
			continue
		}
		singles := make([]compiled, len(items))
		okc := make([]bool, len(items))
		for k, d := range items {
			singles[k], okc[k] = single(j, rows[j].r, d)
		}
		var gone, why []string
		geoDep := false // a site goes because a geosite list holds it
		removed := make([]bool, len(items))
		for k, d := range items {
			if !okc[k] {
				continue
			}
			reason := ""
			for i := range j {
				if rows[i].use && !rows[i].dropped && rows[i].cr.covers(&singles[k]) {
					reason = "его раньше забирает правило «" + rows[i].cr.name + "» (" + routeText(&rows[i].cr, o) + ")"
					geoDep = geoDep || usesGeo(&rows[i].cr)
					break
				}
			}
			for m, e := range items {
				if reason != "" || m == k || !okc[m] || removed[m] || !singles[m].covers(&singles[k]) {
					continue
				}
				// Two that cover each other (the same site twice): the
				// first stays.
				if singles[k].covers(&singles[m]) && k < m {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(e), strings.TrimSpace(d)) {
					reason = "повторяется в этом же правиле"
				} else {
					reason = "его уже покрывает " + strings.TrimSpace(e) + " в этом же правиле"
				}
			}
			if reason != "" {
				removed[k] = true
				gone = append(gone, d)
				why = append(why, strings.TrimSpace(d)+": "+reason)
			}
		}
		if len(gone) == 0 {
			continue
		}
		if len(gone) == len(items) && len(rows[j].r.AllApps()) == 0 && len(rows[j].r.Ports) == 0 {
			// Every site is caught above: the rule never matches.
			rows[j].dropped = true
			t := Tidy{ID: "drop:" + rows[j].id, Kind: TidyDrop, Rules: []string{rows[j].id}, Changes: geoDep,
				Title:   "Удалить правило «" + rows[j].cr.name + "»",
				Details: append([]string{"Никогда не срабатывает: все его сайты раньше забирают правила выше."}, why...)}
			if geoDep {
				t.Details = append(t.Details, geoDepends)
			}
			out = append(out, t)
			continue
		}
		if len(gone) == len(items) {
			continue // a rule left with no sites would match every site
		}
		if geoDep {
			why = append(why, geoDepends)
		}
		out = append(out, Tidy{ID: "sites:" + rows[j].id, Kind: TidySites, Rules: []string{rows[j].id}, Sites: gone, Changes: geoDep,
			Title:   fmt.Sprintf("Убрать из «%s» лишние сайты: %d", rows[j].cr.name, len(gone)),
			Details: why})
	}
	return out
}

// geoDepends says why an item that relies on a geosite list is not ticked
// for the user.
const geoDepends = "Держится на списке geosite правила выше: он меняется с обновлением базы правил или её источником, и тогда эти сайты пойдут по правилам ниже."

// usesGeo: the rule names a geosite list, whose content comes and goes
// with the rule database.
func usesGeo(cr *compiled) bool {
	for i := range cr.doms {
		if cr.doms[i].kind == domGeo {
			return true
		}
	}
	return false
}

// mergeKey: rules that can be merged are sites only (any program) or
// programs only (any site).
func mergeKey(row *tidyRow) (string, bool) {
	cr := &row.cr
	if !row.use || row.dropped || cr.hasApp() == cr.hasDest() {
		return "", false
	}
	kind := "d"
	if cr.hasApp() {
		kind = "a"
	}
	prof := ""
	if cr.action == Tunnel {
		prof = cr.profile
	}
	return strings.Join([]string{kind, fmt.Sprint(uint8(cr.action)), prof, strings.Join(cr.fallback, ","),
		fmt.Sprint(cr.proto), fmt.Sprint(cr.ports)}, "\x00"), true
}

// moveUp tells what moving rule j up to just below base changes: hard
// means some connection would go elsewhere for everyone; soft lists the
// rules between whose programs (or sites) would.
func moveUp(rows []tidyRow, base, j int) (hard bool, soft []int) {
	b := &rows[j].cr
	for k := base + 1; k < j; k++ {
		a := &rows[k]
		if !a.r.On() || a.dropped {
			continue
		}
		cr := a.cr
		if !a.use { // managed: it matches all the same
			c, err := compileRule(k, a.r, currentGeo())
			if err != nil {
				continue
			}
			cr = c
		}
		if sameRuleRoute(&cr, b) {
			continue
		}
		switch overlap(&cr, b) {
		case overlapHard:
			return true, nil
		case overlapSoft:
			soft = append(soft, k)
		}
	}
	return false, soft
}

const (
	overlapNone = iota
	overlapSoft // only for some programs
	overlapHard
)

// overlap: can a connection match both a and b?
func overlap(a, b *compiled) int {
	if a.proto != 0 && b.proto != 0 && a.proto != b.proto {
		return overlapNone
	}
	if len(a.ports) > 0 && len(b.ports) > 0 && !portsMeet(a.ports, b.ports) {
		return overlapNone
	}
	if a.hasDest() && b.hasDest() && !destsMeet(a, b) {
		return overlapNone
	}
	if a.hasApp() && b.hasApp() && !appsMeet(a, b) {
		return overlapNone
	}
	// They meet: for everyone, or, when only one names programs, only for
	// connections of those programs.
	if a.hasApp() != b.hasApp() {
		return overlapSoft
	}
	return overlapHard
}

func portsMeet(a, b []PortRange) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Lo <= y.Hi && y.Lo <= x.Hi {
				return true
			}
		}
	}
	return false
}

func appsMeet(a, b *compiled) bool {
	base := func(p *appPat) string {
		s := p.app
		if p.kind == "path" {
			s = s[strings.LastIndexAny(s, `\/`)+1:]
		}
		return strings.TrimSuffix(s, ".exe") // macOS names have none
	}
	for i := range a.apps {
		for j := range b.apps {
			x, y := &a.apps[i], &b.apps[j]
			// A glob may match the other; a program with its children may
			// start the other one (a game from steam.exe).
			if x.kind == "glob" || y.kind == "glob" || x.inherit || y.inherit || x.app == y.app || base(x) == base(y) {
				return true
			}
		}
	}
	return false
}

// destsMeet: may some destination match an item of both?
func destsMeet(a, b *compiled) bool {
	if len(a.ips) > 0 && len(b.ips) > 0 {
		for i := range a.ips {
			for j := range b.ips {
				x, y := &a.ips[i], &b.ips[j]
				if !x.pfx.IsValid() || !y.pfx.IsValid() || x.pfx.Overlaps(y.pfx) {
					return true
				}
			}
		}
	}
	// A name resolves to any address: names and addresses meet, unless
	// the addresses are local ones no site has.
	if len(a.ips) > 0 && len(b.doms) > 0 && !a.addrLocal || len(b.ips) > 0 && len(a.doms) > 0 && !b.addrLocal {
		return true
	}
	for i := range a.doms {
		for j := range b.doms {
			if domsMeet(&a.doms[i], &b.doms[j]) {
				return true
			}
		}
	}
	return false
}

// someMatcher is a category that can tell whether it may hold a name or
// one under it (geodata.DomainSet).
type someMatcher interface{ MatchSome(name string) bool }

func domsMeet(a, b *domPat) bool {
	if a.kind > b.kind {
		a, b = b, a
	}
	// a.kind <= b.kind: exact < sub < suffix < keyword < regex < geo
	switch {
	case b.kind == domGeo:
		if a.kind == domGeo || b.geo == nil {
			return a.kind == domGeo || b.pending
		}
		switch a.kind {
		case domExact:
			return b.geo.Match(a.dom)
		case domSub, domSuffix:
			m, ok := b.geo.(someMatcher)
			return !ok || m.MatchSome(a.dom)
		}
		return true
	case b.kind >= domKeyword:
		if a.kind == domExact {
			return b.match(a.dom)
		}
		return true // a name under a domain may contain any word
	}
	return a.covers(b) || b.covers(a)
}

func tidyMerges(rows []tidyRow, o TidyOptions) []Tidy {
	type group struct {
		key     string
		members []int
		soft    []int
	}
	var groups []*group
	last := map[string]*group{}
	for j := range rows {
		key, ok := mergeKey(&rows[j])
		if !ok {
			continue
		}
		if g := last[key]; g != nil {
			if hard, soft := moveUp(rows, g.members[0], j); !hard {
				g.members = append(g.members, j)
				for _, k := range soft {
					if !slices.Contains(g.soft, k) {
						g.soft = append(g.soft, k)
					}
				}
				continue
			}
		}
		g := &group{key: key, members: []int{j}}
		groups = append(groups, g)
		last[key] = g
	}
	var out []Tidy
	for _, g := range groups {
		if len(g.members) < 2 {
			continue
		}
		var ids, names []string
		for _, m := range g.members {
			ids = append(ids, rows[m].id)
			names = append(names, "«"+rows[m].cr.name+"»")
		}
		first := &rows[g.members[0]].cr
		t := Tidy{ID: "merge:" + strings.Join(ids, ","), Kind: TidyMerge, Rules: ids, Name: mergedName(rows, g.members),
			Title:   fmt.Sprintf("Объединить %d правил(а) %s в одно", len(ids), routeText(first, o)),
			Details: []string{strings.Join(names, ", ")}}
		if len(g.soft) > 0 {
			var by []string
			for _, k := range g.soft {
				by = append(by, "«"+rows[k].cr.name+"»")
			}
			t.Changes = true
			t.Details = append(t.Details, "Правила "+strings.Join(by, ", ")+" стоят между ними: для их программ (или сайтов) эти соединения пойдут "+routeText(first, o)+".")
		}
		out = append(out, t)
	}
	return out
}

func mergedName(rows []tidyRow, members []int) string {
	var names []string
	for _, m := range members {
		if n := strings.TrimSpace(rows[m].r.Name); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	switch {
	case len(names) == 0:
		return ""
	case len(names) <= 3:
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, %s и ещё %d", names[0], names[1], len(names)-2)
}

// tidyGeo: plain sites of a rule a service's geosite category holds.
func tidyGeo(rows []tidyRow, o TidyOptions) ([]Tidy, string) {
	if o.Categories == nil {
		return nil, ""
	}
	type item struct {
		src  string
		dom  string
		subs bool // the item means its subdomains too
	}
	byRow := map[int][]item{}
	var names []string
	for j := range rows {
		if !rows[j].use || rows[j].dropped || !rows[j].cr.hasDom() {
			continue
		}
		for _, d := range rows[j].r.AllDomains() {
			if IsAddressItem(d) {
				continue
			}
			cr, ok := single(j, rows[j].r, d)
			if !ok || len(cr.doms) != 1 || cr.doms[0].kind > domSuffix {
				continue
			}
			p := cr.doms[0]
			byRow[j] = append(byRow[j], item{src: d, dom: p.dom, subs: p.kind != domExact})
			if !slices.Contains(names, p.dom) {
				names = append(names, p.dom)
			}
		}
	}
	if len(names) == 0 {
		return nil, ""
	}
	cats, err := o.Categories(names)
	if err != nil {
		return nil, err.Error()
	}
	var out []Tidy
	for j := range rows {
		items := byRow[j]
		have := map[string]bool{}
		for _, d := range rows[j].r.AllDomains() {
			have[strings.ToLower(strings.TrimSpace(d))] = true
		}
		left := slices.Clone(items)
		for len(left) > 0 {
			type cand struct {
				name  string
				size  int
				items []item
			}
			best := cand{}
			counts := map[string]*cand{}
			for _, it := range left {
				for _, c := range cats[it.dom] {
					if it.subs && !c.Subdomains || have["geosite:"+c.Name] {
						continue
					}
					cc := counts[c.Name]
					if cc == nil {
						cc = &cand{name: c.Name, size: c.Size}
						counts[c.Name] = cc
					}
					cc.items = append(cc.items, it)
				}
			}
			for _, c := range counts {
				if len(c.items) == 1 && !relatedName(c.name, c.items[0].dom) {
					continue
				}
				if len(c.items) > len(best.items) || len(c.items) == len(best.items) && (c.size < best.size || c.size == best.size && c.name < best.name) {
					best = *c
				}
			}
			if len(best.items) == 0 {
				break
			}
			var srcs []string
			for _, it := range best.items {
				srcs = append(srcs, it.src)
			}
			out = append(out, Tidy{ID: "geo:" + rows[j].id + ":" + best.name, Kind: TidyGeo, Rules: []string{rows[j].id},
				Sites: srcs, Category: "geosite:" + best.name, Changes: true,
				Title:   fmt.Sprintf("«%s»: заменить %s списком geosite:%s", rows[j].cr.name, sitesText(srcs), best.name),
				Details: []string{fmt.Sprintf("В списке %d записей: правило поймает и другие адреса этого сервиса, а список обновляется вместе с базой правил.", best.size)}})
			left = slices.DeleteFunc(left, func(it item) bool {
				return slices.ContainsFunc(best.items, func(b item) bool { return b.src == it.src })
			})
		}
	}
	return out, ""
}

func sitesText(s []string) string {
	if len(s) <= 3 {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s, %s и ещё %d", s[0], s[1], len(s)-2)
}

// relatedName: a category named like the site (youtube for youtube.com,
// m.youtube.com; discord for discord.gg): one site is enough for it.
func relatedName(cat, dom string) bool {
	labels := strings.Split(dom, ".")
	for _, l := range labels[:len(labels)-1] {
		if l == cat {
			return true
		}
	}
	return false
}

// ApplyTidy applies the accepted suggestions (their IDs) of TidyRules(c,
// o) and returns the rules. A merge is checked again on the list as the
// other changes left it: a rule it can no longer move stays where it is.
func ApplyTidy(c Config, o TidyOptions, accept []string) Config {
	all := TidyRules(c, o).Items
	ok := map[string]bool{}
	for _, a := range accept {
		ok[a] = true
	}
	out := c
	out.Rules = slices.Clone(c.Rules)
	for i := range out.Rules {
		out.Rules[i] = out.Rules[i].Clone()
		out.Rules[i].ID = tidyID(i, out.Rules[i])
	}
	at := func(id string) int {
		return slices.IndexFunc(out.Rules, func(r Rule) bool { return r.ID == id })
	}
	for _, kind := range []string{TidyDrop, TidySites, TidyGeo, TidyMerge} {
		for _, t := range all {
			if t.Kind != kind || !ok[t.ID] {
				continue
			}
			switch kind {
			case TidyDrop:
				if i := at(t.Rules[0]); i >= 0 {
					out.Rules = slices.Delete(out.Rules, i, i+1)
				}
			case TidySites, TidyGeo:
				i := at(t.Rules[0])
				if i < 0 {
					continue
				}
				r := &out.Rules[i]
				r.Domains = r.AllDomains()
				r.Domain = nil
				n := len(r.Domains)
				for _, d := range t.Sites { // of a repeat, the first stays
					for k := len(r.Domains) - 1; k >= 0; k-- {
						if r.Domains[k] == d {
							r.Domains = slices.Delete(r.Domains, k, k+1)
							break
						}
					}
				}
				if kind == TidyGeo && len(r.Domains) < n && !slices.Contains(r.Domains, t.Category) {
					r.Domains = append(r.Domains, t.Category)
				}
				if len(r.Domains) == 0 {
					r.Domains = nil
					if len(r.AllApps()) == 0 && len(r.Ports) == 0 {
						out.Rules = slices.Delete(out.Rules, i, i+1) // every site caught above
					}
				}
			case TidyMerge:
				applyMerge(&out, o, t)
			}
		}
	}
	for i := range out.Rules {
		if strings.HasPrefix(out.Rules[i].ID, "#") {
			out.Rules[i].ID = ""
		}
	}
	return out
}

func applyMerge(c *Config, o TidyOptions, t Tidy) {
	rows := tidyRows(*c, o)
	pos := func(id string) int { return slices.IndexFunc(rows, func(r tidyRow) bool { return r.id == id }) }
	base := -1
	var key string
	var take []int
	for _, id := range t.Rules {
		j := pos(id)
		if j < 0 {
			continue
		}
		k, ok := mergeKey(&rows[j])
		if !ok {
			continue
		}
		if base < 0 {
			base, key = j, k
			continue
		}
		if k != key || j < base {
			continue
		}
		if hard, soft := moveUp(rows, base, j); hard || len(soft) > 0 && !t.Changes {
			continue
		}
		take = append(take, j)
	}
	if base < 0 || len(take) == 0 {
		return
	}
	m := c.Rules[base].Clone()
	m.Domains, m.Domain = m.AllDomains(), nil
	m.Apps, m.App = m.AllApps(), nil
	for _, j := range take {
		for _, d := range c.Rules[j].AllDomains() {
			if !slices.Contains(m.Domains, d) {
				m.Domains = append(m.Domains, d)
			}
		}
		for _, a := range c.Rules[j].AllApps() {
			if !slices.Contains(m.Apps, a) {
				m.Apps = append(m.Apps, a)
			}
		}
	}
	if len(m.Domains) == 0 {
		m.Domains = nil
	}
	if len(m.Apps) == 0 {
		m.Apps = nil
	}
	if t.Name != "" && len(take)+1 == len(t.Rules) {
		m.Name = t.Name
	}
	c.Rules[base] = m
	for i := len(take) - 1; i >= 0; i-- {
		c.Rules = slices.Delete(c.Rules, take[i], take[i]+1)
	}
}
