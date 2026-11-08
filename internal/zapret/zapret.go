// Package zapret builds the command line of winws2 (bol-van/zapret2, MIT),
// the DPI bypass HyRoute runs beside its engine on Windows, and checks
// whether the bypass works.
//
// HyRoute's own WinDivert handle sits above winws2's (priority 1000 and
// 0, docs/architecture/interception.md): what HyRoute sends direct reaches
// winws2, what it sends through a tunnel never does. So a target («YouTube»,
// «Discord», the user's sites) goes through the bypass when its traffic goes
// direct and matches the profiles built here.
//
// The command line is built only from the blocks of this package. Nothing
// the user types becomes an option: winws2 runs with administrator rights,
// and an option like --lua-init runs code (security: settings live in a
// folder the user can write).
package zapret

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Target is what goes through the bypass.
type Target string

const (
	YouTube Target = "youtube"
	Discord Target = "discord"
	Sites   Target = "sites" // the user's sites
)

// Targets in the order profiles are built and shown.
var Targets = []Target{YouTube, Discord, Sites}

// TargetName is a target for the UI.
func TargetName(t Target) string {
	switch t {
	case YouTube:
		return "YouTube"
	case Discord:
		return "Discord"
	case Sites:
		return "Свои сайты"
	}
	return string(t)
}

// Method choices besides a Method's ID.
const (
	// Auto: no method fixed: the bypass tries the methods in turn and
	// switches on failures (zapret2's circular orchestrator), starting
	// with the one picked for this network when there is one.
	Auto = ""
	// None: the target is not blocked here: no profile for it.
	None = "none"
	// VPN: the target goes through HyRoute's main server instead (a
	// bypass cannot open what is blocked by address); the user's choice only.
	VPN = "vpn"
)

// Method is a desync recipe for TLS (and HTTP) over TCP: the --lua-desync
// instances of a profile. {host} is replaced by a decoy host name fitting
// the target (hostfakesplit).
type Method struct {
	ID   string
	Name string
	tcp  []string
}

// Methods, the order auto-pick tries them in and circular rotates
// through: the most often working first. Adapted from the presets of
// TheFirstNoob/Zapret-2-GUI (MIT), built on zapret2's zapret-antidpi.lua.
var Methods = []Method{
	// The fakes die by TCP MD5 or by TTL: Windows sends no TCP timestamps,
	// so the presets' tcp_ts=-1000 spoils nothing there and the fake
	// reaches the server, which breaks the handshake (Windows CI: example.com
	// through each method). tcp_md5 keeps tcp_ts: on a system with
	// timestamps both spoil it.
	{ID: "fake-seqovl", Name: "Фейк (TTL по расстоянию) + разрез с перекрытием", tcp: []string{
		"fake:blob=google_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:repeats=8",
		"multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=google_tls"}},
	{ID: "fake-seqovl-mod", Name: "Фейк со случайными полями + разрез с перекрытием", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=8:tls_mod=rnd,dupsid",
		"multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=google_tls"}},
	{ID: "fake-md5-seqovl", Name: "Фейк с TCP MD5 + разрез с перекрытием", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:repeats=7:tcp_md5",
		"multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=google_tls"}},
	{ID: "seqovl", Name: "Разрез с перекрытием", tcp: []string{
		"multisplit:pos=2:seqovl=681:seqovl_pattern=google_tls:repeats=7",
		"multisplit:pos=2,midsld:repeats=7"}},
	{ID: "fake", Name: "Только фейк", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7"}},
	{ID: "fake-disorder", Name: "Фейк + перестановка частей", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7",
		"multidisorder:pos=1,midsld"}},
	// fakedsplit's fake parts are spoiled as its fakes are, and filled with
	// the pattern (its "blob" would split that blob instead of the real
	// ClientHello).
	{ID: "fakedsplit", Name: "Фейк + разрез с фейковыми частями", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7",
		"fakedsplit:pos=2:pattern=google_tls:tcp_ts=-1000:tcp_md5"}},
	{ID: "hostfakesplit", Name: "Фейк + подмена имени сайта в части", tcp: []string{
		"fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7",
		"hostfakesplit:host={host}:tcp_ts=-1000:tcp_md5"}},
	// Under a white-listed name (vk.com): against the "16-20 KB" cut of
	// CDN addresses (Discord's media on Cloudflare), as Flowseal's general
	// list does with 4pda.to.
	{ID: "seqovl-vk", Name: "Разрез с перекрытием под vk.com", tcp: []string{
		"multisplit:pos=1:seqovl=568:seqovl_pattern=vk_tls"}},
	{ID: "fake-vk-seqovl", Name: "Фейк vk.com + разрез с перекрытием", tcp: []string{
		"fake:blob=vk_tls:tcp_ts=-1000:tcp_md5:repeats=6",
		"multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=vk_tls"}},
	{ID: "hostfakesplit-vk", Name: "Фейк vk.com + подмена имени на vk.com", tcp: []string{
		"fake:blob=vk_tls:tcp_ts=-1000:tcp_md5:repeats=6",
		"hostfakesplit:host=vk.com:tcp_ts=-1000:tcp_md5"}},
}

// FindMethod is a method by ID.
func FindMethod(id string) (Method, bool) {
	if st, ok := ParseStrategy(id); ok {
		return Method{ID: id, Name: st.Name(), tcp: st.instances()}, true
	}
	i := slices.IndexFunc(Methods, func(m Method) bool { return m.ID == id })
	if i < 0 {
		return Method{}, false
	}
	return Methods[i], true
}

// MethodName is a method choice for the UI.
func MethodName(id string) string {
	switch id {
	case Auto:
		return "Автоматически"
	case None:
		return "Не нужен: не блокируется"
	case VPN:
		return "Через VPN"
	}
	if m, ok := FindMethod(id); ok {
		return m.Name
	}
	return id
}

// Settings are zapret.json: the user's choices and what auto-pick found.
type Settings struct {
	Enabled bool     `json:"enabled"`
	Targets []Target `json:"targets"`
	// Sites: the user's domains (Target Sites).
	Sites []string `json:"sites,omitempty"`
	// Methods: a method fixed by the user per target (absent = Auto).
	Methods map[Target]string `json:"methods,omitempty"`
	// Picked: what auto-pick found, per network (NetKey).
	Picked map[string]Picked `json:"picked,omitempty"`
}

// Picked is one auto-pick's result for a network.
type Picked struct {
	At      time.Time         `json:"at"`
	Methods map[Target]string `json:"methods"` // a method ID or None
	// Working: every method that opened the target, fastest first (the
	// first is Methods[t]). The circular plan tries them before the rest.
	Working map[Target][]string `json:"working,omitempty"`
}

// Limits.
const (
	MaxSites   = 500
	MaxNetKeys = 32
)

// On reports that t goes through the bypass.
func (s Settings) On(t Target) bool { return s.Enabled && slices.Contains(s.Targets, t) }

// Normalize trims and dedups the sites, drops unknown targets and methods.
func (s *Settings) Normalize() {
	var ts []Target
	for _, t := range s.Targets {
		if slices.Contains(Targets, t) && !slices.Contains(ts, t) {
			ts = append(ts, t)
		}
	}
	s.Targets = ts
	var sites []string
	for _, d := range s.Sites {
		d = NormalizeSite(d)
		if d != "" && !slices.Contains(sites, d) {
			sites = append(sites, d)
		}
	}
	s.Sites = sites
	known := func(m string) bool { _, ok := FindMethod(m); return ok }
	for t, m := range s.Methods {
		if !known(m) && m != None && m != VPN || !slices.Contains(Targets, t) {
			delete(s.Methods, t)
		}
	}
	// Methods a newer or older HyRoute picked that this one does not know.
	for k, pk := range s.Picked {
		for t, m := range pk.Methods {
			if !known(m) && m != None {
				delete(pk.Methods, t)
			}
		}
		for t, ms := range pk.Working {
			pk.Working[t] = slices.DeleteFunc(ms, func(m string) bool { return !known(m) })
		}
		s.Picked[k] = pk
	}
}

// Validate checks what Normalize cannot fix.
func (s Settings) Validate() error {
	if len(s.Sites) > MaxSites {
		return fmt.Errorf("сайтов может быть не больше %d", MaxSites)
	}
	for _, d := range s.Sites {
		if NormalizeSite(d) != d {
			return fmt.Errorf("«%s» — не имя сайта и не внешний адрес или сеть", d)
		}
	}
	if len(s.Picked) > MaxNetKeys {
		return errors.New("слишком много сетей с подобранными методами")
	}
	return nil
}

// NormalizeSite turns what the user typed into a list entry: a host name
// («https://www.Example.com/x» → «www.example.com»), an address
// («1.2.3.4», «[2001:db8::1]:443» → «2001:db8::1») or a network
// («104.16.1.0/13» → «104.16.0.0/13»); "" when it is none of them.
func NormalizeSite(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if p, ok := siteNet(s); ok {
		return p
	}
	if a, bits, ok := strings.Cut(s, "/"); ok && bits != "" && strings.Trim(bits, "0123456789") == "" {
		if _, err := netip.ParseAddr(a); err == nil {
			return "" // a network that is local, too wide or not one
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if p, ok := siteNet(s); ok { // an address with a path
		return p
	}
	if h, _, err := net.SplitHostPort(s); err == nil { // with a port
		if p, ok := siteNet(h); ok {
			return p
		}
		s = h
	}
	s = strings.Trim(strings.TrimPrefix(s, "*."), ".")
	if !validSite(s) || isAddrLike(s) {
		return ""
	}
	return s
}

// siteNet reads an address or network entry, canonical: the network
// masked, a single address without its /32 or /128.
func siteNet(s string) (string, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(strings.Trim(s, "[]"))
		if aerr != nil || a.Zone() != "" {
			return "", false
		}
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-map[bool]int{true: 96, false: 0}[p.Addr().Is4In6()]).Masked()
	if !validNet(p) {
		return "", false
	}
	if p.IsSingleIP() {
		return p.Addr().String(), true
	}
	return p.String(), true
}

// notPublic: networks no site of the user's lives in. An entry touching
// them would send the user's own network or the like through winws2.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/127"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// validNet: a public address or network no wider than /8 (IPv4) or /16
// (IPv6): wider would put a good part of the internet through winws2.
func validNet(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
		return false
	}
	for _, np := range notPublic {
		if p.Overlaps(np) {
			return false
		}
	}
	return true
}

// isAddrLike: digits and dots only, as an address that did not parse
// (1.2.3, 1.2.3.400): never a site name.
func isAddrLike(s string) bool {
	return strings.Trim(s, "0123456789.") == ""
}

// SiteNames are the host names of sites, SiteNets their addresses and
// networks (canonical entries, as NormalizeSite gives).
func SiteNames(sites []string) []string {
	var out []string
	for _, s := range sites {
		if _, ok := siteNet(s); !ok {
			out = append(out, s)
		}
	}
	return out
}

func SiteNets(sites []string) []string {
	var out []string
	for _, s := range sites {
		if _, ok := siteNet(s); ok {
			out = append(out, s)
		}
	}
	return out
}

// validSite: letters, digits, hyphens and dots, with a dot, at most 253
// bytes. Nothing a hostlist line or a command line could misread.
func validSite(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return !strings.Contains(s, "..")
}

// Plan is how one target is processed: the methods in order; with
// Circular the bypass switches between them on failures, else it uses
// the first.
type Plan struct {
	Methods  []string
	Circular bool
}

// PlanFor resolves the plan of t: the user's fixed method, else Auto with
// the method auto-pick found on this network first. ok is false when the
// target needs no bypass here (auto-pick found it unblocked).
func (s Settings) PlanFor(t Target, netKey string) (p Plan, ok bool) {
	if m := s.Methods[t]; m != Auto {
		if m == None || m == VPN {
			return Plan{}, false
		}
		return Plan{Methods: []string{m}}, true
	}
	pk := s.Picked[netKey]
	first := pk.Methods[t]
	if first == None {
		return Plan{}, false
	}
	// What opened the target here first (fastest first), then the rest.
	p.Circular = true
	if first != "" && !slices.Contains(pk.Working[t], first) {
		p.Methods = append(p.Methods, first)
	}
	for _, m := range pk.Working[t] {
		if !slices.Contains(p.Methods, m) {
			p.Methods = append(p.Methods, m)
		}
	}
	for _, m := range Methods {
		if !slices.Contains(p.Methods, m.ID) {
			p.Methods = append(p.Methods, m.ID)
		}
	}
	return p, true
}
