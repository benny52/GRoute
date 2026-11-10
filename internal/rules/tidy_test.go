package rules

import (
	"slices"
	"strings"
	"testing"
)

func (f fakeSite) MatchAll(n string) bool { return f.Match(n) }
func (f fakeSite) MatchSome(n string) bool {
	if f.Match(n) {
		return true
	}
	for k := range f {
		if strings.HasSuffix(k, "."+n) {
			return true
		}
	}
	return false
}

func tidyIDs(r TidyResult) []string {
	var out []string
	for _, t := range r.Items {
		out = append(out, t.ID)
	}
	return out
}

func ids(c Config) []string {
	var out []string
	for _, r := range c.Rules {
		out = append(out, r.ID+"="+strings.Join(r.AllDomains(), "+")+strings.Join(appNames(r), "+"))
	}
	return out
}

func appNames(r Rule) []string {
	var out []string
	for _, a := range r.AllApps() {
		out = append(out, a.Pattern)
	}
	return out
}

func TestTidyDropsAndSites(t *testing.T) {
	withGeo(t, fakeGeo{})
	off := false
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{ID: "dpi", Name: "Обход DPI: YouTube", Domains: []string{".youtube.com"}, Action: Direct},
		{ID: "yt", Name: "YouTube", Domains: []string{"geosite:youtube"}, Action: Tunnel, Profile: "nl"},
		{ID: "yt2", Name: "Ютуб", Domains: []string{".youtube.com", "www.youtube.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "mix", Name: "Разное", Domains: []string{".x.com", "a.x.com", ".x.com", "googlevideo.com", ".y.com"}, Action: Tunnel, Profile: "de"},
		{ID: "off", Name: "Выкл", Domains: []string{".youtube.com"}, Action: Block, Enabled: &off},
		{ID: "steam", Name: "Steam", Apps: []AppMatch{{Pattern: "steam.exe"}}, Action: Direct},
	}}
	o := TidyOptions{Managed: func(r Rule) bool { return strings.HasPrefix(r.Name, "Обход DPI") },
		Route: func(id string) string {
			return map[string]string{"nl": "Нидерланды", "de": "Германия"}[id]
		}}
	res := TidyRules(c, o)
	// The DPI rule is not counted as catching (it comes and goes): yt2 is
	// dropped for yt (geosite:youtube has youtube.com and below), not for
	// it; mix loses its repeats and the site yt gets first.
	if got := tidyIDs(res); !slices.Equal(got, []string{"drop:yt2", "sites:mix"}) {
		t.Fatalf("%v\n%+v", got, res.Items)
	}
	if s := res.Items[1].Sites; !slices.Equal(s, []string{"a.x.com", ".x.com", "googlevideo.com"}) {
		t.Fatalf("%v %v", s, res.Items[1].Details)
	}
	if d := strings.Join(res.Items[1].Details, "\n"); !strings.Contains(d, "googlevideo.com: его раньше забирает правило «YouTube» (через «Нидерланды»)") {
		t.Fatal(d)
	}
	out := ApplyTidy(c, o, []string{"drop:yt2", "sites:mix"})
	if got := ids(out); !slices.Equal(got, []string{"dpi=.youtube.com", "yt=geosite:youtube", "mix=.x.com+.y.com", "off=.youtube.com", "steam=steam.exe"}) {
		t.Fatalf("%v", got)
	}
	// Nothing accepted: nothing changes; the input is not touched.
	if got := ids(ApplyTidy(c, o, nil)); len(got) != 6 || c.Rules[3].Domains[1] != "a.x.com" {
		t.Fatalf("%v", got)
	}
	// Every site caught above: the rule goes as a whole.
	c2 := Config{Rules: []Rule{
		{ID: "a", Domains: []string{".a.com"}, Action: Direct},
		{ID: "b", Domains: []string{".b.com"}, Action: Block},
		{ID: "ab", Domains: []string{"x.a.com", ".b.com"}, Action: Tunnel},
	}}
	if got := tidyIDs(TidyRules(c2, TidyOptions{})); !slices.Equal(got, []string{"drop:ab"}) {
		t.Fatalf("%v", got)
	}
}

func TestTidyMerge(t *testing.T) {
	withGeo(t, fakeGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{ID: "1", Name: "Видео", Domains: []string{".youtube.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "2", Name: "Мессенджеры", Apps: []AppMatch{{Pattern: "Discord.exe"}}, Action: Tunnel, Profile: "nl"},
		{ID: "3", Name: "Instagram", Domains: []string{".instagram.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "4", Name: "Банк", Domains: []string{".bank.ru"}, Action: Direct},
		{ID: "5", Name: " видео ", Domains: []string{".twitch.tv", ".youtube.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "6", Name: "Steam", Apps: []AppMatch{{Pattern: "steam.exe"}}, Action: Direct},
		{ID: "7", Name: "Видео", Domains: []string{".vimeo.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "8", Name: "Всё .com напрямую", Domains: []string{"keyword:com"}, Action: Direct},
		{ID: "9", Name: "Видео", Domains: []string{".kick.com"}, Action: Tunnel, Profile: "nl"},
		{ID: "10", Name: "Видео", Domains: []string{".rutube.ru"}, Action: Tunnel, Profile: "de"},
		{ID: "11", Name: "Мессенджеры", Apps: []AppMatch{{Pattern: "Telegram.exe"}}, Action: Tunnel, Profile: "nl"},
	}}
	o := TidyOptions{Route: func(id string) string { return map[string]string{"nl": "Нидерланды"}[id] }}
	res := TidyRules(c, o)
	var merges []Tidy
	for _, t := range res.Items {
		if t.Kind == TidyMerge {
			merges = append(merges, t)
		}
	}
	// A merge is the pieces of one rule: «Видео» to one server (1, 5, 7),
	// whatever the case and spaces of the name. «Instagram» to the same
	// server is another rule and stays one; so does «Видео» to another
	// server (10). «Банк» between is about other sites, Steam only for its
	// program (Changes). keyword:com may match kick.com's subdomains: 9
	// stays. 2 and 11 (programs) merge past site rules, whose sites change
	// for those programs.
	if len(merges) != 2 || !slices.Equal(merges[0].Rules, []string{"1", "5", "7"}) || !merges[0].Changes || merges[0].Name != "Видео" ||
		merges[0].Title != "Объединить 3 правила «Видео» (через «Нидерланды») в одно" ||
		merges[0].Details[0] != "В одном правиле будет: .youtube.com, .twitch.tv, .vimeo.com." ||
		!slices.Equal(merges[1].Rules, []string{"2", "11"}) || !merges[1].Changes || merges[1].Name != "Мессенджеры" {
		t.Fatalf("%+v", merges)
	}
	out := ApplyTidy(c, o, []string{merges[0].ID})
	if got := ids(out); !slices.Equal(got, []string{"1=.youtube.com+.twitch.tv+.vimeo.com", "2=Discord.exe", "3=.instagram.com", "4=.bank.ru",
		"6=steam.exe", "8=keyword:com", "9=.kick.com", "10=.rutube.ru", "11=Telegram.exe"}) || out.Rules[0].Name != "Видео" {
		t.Fatalf("%v", got)
	}
	// Nothing left to suggest of what was applied.
	for _, t2 := range TidyRules(out, o).Items {
		if t2.Kind == TidyMerge && slices.Contains(t2.Rules, "1") {
			t.Fatalf("left: %+v", t2)
		}
	}
	// Without Steam between, nothing changes: not flagged.
	c.Rules = slices.DeleteFunc(c.Rules, func(r Rule) bool { return r.ID == "6" || r.ID == "2" || r.ID == "11" })
	for _, t2 := range TidyRules(c, TidyOptions{}).Items {
		if t2.Kind == TidyMerge && t2.Changes {
			t.Fatalf("%+v", t2)
		}
	}
	// Rules the app puts together itself are not taken.
	no := TidyOptions{Kept: func(r Rule) bool { return strings.EqualFold(strings.TrimSpace(r.Name), "видео") }}
	if got := tidyIDs(TidyRules(c, no)); slices.ContainsFunc(got, func(id string) bool { return strings.HasPrefix(id, "merge:") }) {
		t.Fatalf("%v", got)
	}
	// A named rule and a nameless one are not one rule: «YouTube» would
	// come out holding the other's sites. Nameless ones are.
	c2 := Config{Rules: []Rule{
		{ID: "n1", Domains: []string{".a.com"}, Action: Tunnel},
		{ID: "yt", Name: "YouTube", Domains: []string{".youtube.com"}, Action: Tunnel},
		{ID: "n2", Domains: []string{".b.com"}, Action: Tunnel},
	}}
	res = TidyRules(c2, TidyOptions{})
	if got := tidyIDs(res); !slices.Equal(got, []string{"merge:n1,n2"}) || res.Items[0].Name != "" ||
		res.Items[0].Title != "Объединить 2 правила без названия (через VPN) в одно" {
		t.Fatalf("%v %+v", got, res.Items)
	}
	if out := ApplyTidy(c2, TidyOptions{}, []string{"merge:n1,n2"}); !slices.Equal(ids(out), []string{"n1=.a.com+.b.com", "yt=.youtube.com"}) || out.Rules[0].Name != "" {
		t.Fatalf("%v", ids(out))
	}
	// What a merge makes idle goes with it: «Сайт b» repeats the merged
	// rule once .b.com is above it.
	c4 := Config{Rules: []Rule{
		{ID: "x1", Name: "X", Domains: []string{".a.com"}, Action: Tunnel},
		{ID: "y", Name: "Сайт b", Domains: []string{"www.b.com"}, Action: Tunnel},
		{ID: "x2", Name: "X", Domains: []string{".b.com"}, Action: Tunnel},
	}}
	if got := tidyIDs(TidyRules(c4, TidyOptions{})); !slices.Equal(got, []string{"merge:x1,x2"}) {
		t.Fatalf("%v", got)
	}
	out4 := ApplyTidy(c4, TidyOptions{}, []string{"merge:x1,x2"})
	if got := ids(out4); !slices.Equal(got, []string{"x1=.a.com+.b.com"}) || len(TidyRules(out4, TidyOptions{}).Items) != 0 {
		t.Fatalf("%v", got)
	}
	// A site rule between with an overlapping site and another route.
	c3 := Config{Rules: []Rule{
		{ID: "a", Domains: []string{".a.com"}, Action: Tunnel},
		{ID: "b", Domains: []string{"x.c.com"}, Action: Direct},
		{ID: "c", Domains: []string{".c.com"}, Action: Tunnel},
		{ID: "ip", Domains: []string{"1.2.3.0/24"}, Action: Direct},
		{ID: "d", Domains: []string{".d.com"}, Action: Tunnel},
		{ID: "lan", Domains: []string{"192.168.0.0/16"}, Action: Direct},
		{ID: "e", Domains: []string{".e.com"}, Action: Tunnel},
	}}
	got := tidyIDs(TidyRules(c3, TidyOptions{}))
	if !slices.Equal(got, []string{"merge:ip,lan", "merge:d,e"}) { // a local network meets no site
		t.Fatalf("%v", got)
	}
	// CanMoveUp is the same check, for the app's own merges.
	for _, m := range []struct {
		base, j int
		want    bool
	}{{0, 2, false}, {0, 4, false}, {4, 6, true}, {3, 5, true}} {
		if got, soft := CanMoveUp(c3, TidyOptions{}, m.base, m.j); got != m.want || len(soft) != 0 {
			t.Errorf("rule %d up to %d: %v %v", m.j, m.base, got, soft)
		}
	}
	for _, m := range [][2]int{{3, 1}, {0, 9}} {
		if ok, _ := CanMoveUp(c3, TidyOptions{}, m[0], m[1]); ok {
			t.Errorf("moved %v", m)
		}
	}
	if ok, _ := CanMoveUp(c3, TidyOptions{Managed: func(r Rule) bool { return r.ID == "e" }}, 4, 6); ok {
		t.Error("moved a managed rule")
	}
	// A program's rule between: movable, and named.
	c5 := Config{Rules: []Rule{
		{ID: "a", Domains: []string{".a.com"}, Action: Tunnel},
		{ID: "app", Name: "Steam", Apps: []AppMatch{{Pattern: "steam.exe"}}, Action: Direct},
		{ID: "b", Domains: []string{".b.com"}, Action: Tunnel},
	}}
	if ok, soft := CanMoveUp(c5, TidyOptions{}, 0, 2); !ok || !slices.Equal(soft, []string{"Steam"}) {
		t.Errorf("%v %v", ok, soft)
	}
}

func TestTidyGeo(t *testing.T) {
	withGeo(t, fakeGeo{})
	c := Config{Rules: []Rule{
		{ID: "v", Name: "Видео", Domains: []string{".youtube.com", "ytimg.com", ".twitch.tv", "1.2.3.4"}, Action: Tunnel},
		{ID: "d", Name: "Дискорд", Domains: []string{".discord.gg"}, Action: Tunnel},
		{ID: "o", Name: "Одиночка", Domains: []string{".chatgpt.com"}, Action: Tunnel},
		{ID: "f", Name: "Только имя", Domains: []string{"www.twitch.tv", ".twitch.tv"}, Action: Tunnel},
		{ID: "k", Name: "Кик", Domains: []string{".kick.com"}, Action: Tunnel},
		{ID: "y2", Name: "Ещё видео", Domains: []string{"geosite:youtube", ".vimeo.com"}, Action: Tunnel},
	}}
	cats := map[string][]SiteCategory{
		"youtube.com": {{Name: "youtube", Size: 120, Subdomains: true}, {Name: "google", Size: 900, Subdomains: true}},
		"ytimg.com":   {{Name: "youtube", Size: 120, Subdomains: true}, {Name: "google", Size: 900, Subdomains: true}},
		"twitch.tv":   {{Name: "twitch", Size: 30, Subdomains: false}},
		"discord.gg":  {{Name: "discord", Size: 40, Subdomains: true}},
		"chatgpt.com": {{Name: "openai", Size: 60, Subdomains: true}},
		"kick.com":    {{Name: "kick", Size: 1, Subdomains: true}},
	}
	o := TidyOptions{Categories: func(names []string) (map[string][]SiteCategory, error) { return cats, nil }}
	res := TidyRules(c, o)
	var got []string
	for _, t := range res.Items {
		if t.Kind == TidyGeo {
			got = append(got, t.ID+"="+strings.Join(t.Sites, "+"))
		}
	}
	// youtube: 2 sites, the smaller list; twitch: its list has twitch.tv
	// only by full name, not .twitch.tv's subdomains; discord: one site,
	// but the list is named after it; openai: one site, another name;
	// kick: a list of one entry is no more than the rule names already.
	// A rule a tool keeps as plain sites gets no list.
	if !slices.Equal(got, []string{"geo:v:youtube=.youtube.com+ytimg.com", "geo:d:discord=.discord.gg"}) {
		t.Fatalf("%v", got)
	}
	kept := o
	kept.Kept = func(r Rule) bool { return r.ID == "v" }
	if got := tidyIDs(TidyRules(c, kept)); slices.Contains(got, "geo:v:youtube") || !slices.Contains(got, "geo:d:discord") {
		t.Fatalf("%v", got)
	}
	out := ApplyTidy(c, o, []string{"geo:v:youtube", "geo:d:discord"})
	// The list now in «Видео» is the one «Ещё видео» below names. That
	// item is idle only as long as the list above is there: it stays, for
	// the user to decide.
	if g := ids(out); g[0] != "v=.twitch.tv+1.2.3.4+geosite:youtube" || g[1] != "d=geosite:discord" || g[5] != "y2=geosite:youtube+.vimeo.com" {
		t.Fatalf("%v", g)
	}
}

// A program rule «with its children» between two others may take their
// programs (a game started by Steam): no merge moves past it.
func TestTidyMergeInheritChildren(t *testing.T) {
	withGeo(t, fakeGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{ID: "g1", Apps: []AppMatch{{Pattern: "game1.exe"}}, Action: Direct},
		{ID: "steam", Apps: []AppMatch{{Pattern: "steam.exe", InheritChildren: true}}, Action: Tunnel},
		{ID: "g2", Apps: []AppMatch{{Pattern: "game2.exe"}}, Action: Direct},
	}}
	for _, it := range TidyRules(c, TidyOptions{}).Items {
		if it.Kind == TidyMerge {
			t.Fatalf("%+v", it)
		}
	}
}

// A drop or a site that goes because a geosite list holds it is a change:
// the list comes and goes with the rule database, so it is not ticked.
func TestTidyGeoDependsIsChange(t *testing.T) {
	withGeo(t, fakeGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{ID: "yt", Domains: []string{"geosite:youtube"}, Action: Tunnel},
		{ID: "yt2", Domains: []string{".youtube.com"}, Action: Tunnel},
		{ID: "a", Domains: []string{".a.com"}, Action: Direct},
		{ID: "a2", Domains: []string{"x.a.com"}, Action: Direct},
	}}
	got := map[string]bool{}
	for _, it := range TidyRules(c, TidyOptions{}).Items {
		got[it.ID] = it.Changes
	}
	if c, ok := got["drop:yt2"]; !ok || !c {
		t.Fatalf("geosite drop: %v", got)
	}
	if c, ok := got["drop:a2"]; !ok || c {
		t.Fatalf("plain drop: %v", got)
	}
}
