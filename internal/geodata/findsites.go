package geodata

import (
	"sort"
	"strings"
	"sync"
)

// SiteCover is a geosite category that contains a name.
type SiteCover struct {
	Category string
	Size     int // entries in the category
	// Subdomains: every subdomain of the name is in the category too (a
	// domain: or keyword: entry matched, not only full: or regexp:).
	Subdomains bool
}

// FindSites is FindSite for many names at once: each category is read
// once. names are normalized (lower case, no trailing dot); the result has
// an entry for each name found in some category, categories by name.
func (db *DB) FindSites(names []string) (map[string][]SiteCover, error) {
	path, cats, f, err := db.spans(Site)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	out := map[string][]SiteCover{}
	var firstErr error
	parallel(cats, func(cat string) {
		b, err := readSpan(path, f.index[cat])
		var found map[string]bool
		size := 0
		if err == nil {
			found, size, err = coverNames(b, names)
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		for n, sub := range found {
			out[n] = append(out[n], SiteCover{Category: cat, Size: size, Subdomains: sub})
		}
	})
	for _, v := range out {
		sort.Slice(v, func(i, j int) bool { return v[i].Category < v[j].Category })
	}
	return out, firstErr
}

// coverNames decodes one category and tests every name against it: name →
// whether its subdomains are covered too.
func coverNames(b []byte, names []string) (map[string]bool, int, error) {
	domains, full := map[string]bool{}, map[string]bool{}
	var words []string
	var res []func(string) bool
	n := 0
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil, 0, err
		}
		if num != 2 || wire != 2 {
			if err := p.skip(wire); err != nil {
				return nil, 0, err
			}
			continue
		}
		raw, err := p.bytes()
		if err != nil {
			return nil, 0, err
		}
		n++
		typ, val, _, err := decodeDomain(raw)
		if err != nil {
			return nil, 0, err
		}
		val = normValue(typ, val)
		switch typ {
		case typeFull:
			full[val] = true
		case typeDomain:
			domains[val] = true
		case typePlain:
			if val != "" {
				words = append(words, val)
			}
		case typeRegex:
			if re := compileLoose(val); re != nil {
				res = append(res, re)
			}
		}
	}
	found := map[string]bool{}
	for _, name := range names {
		sub, ok := false, false
		for d := name; d != "" && !sub; {
			if domains[d] {
				sub, ok = true, true
			}
			_, rest, more := strings.Cut(d, ".")
			if !more {
				break
			}
			d = rest
		}
		for _, w := range words {
			if !sub && strings.Contains(name, w) {
				sub, ok = true, true
			}
		}
		if !ok && full[name] {
			ok = true
		}
		for _, re := range res {
			if !ok && re(name) {
				ok = true
			}
		}
		if ok {
			found[name] = sub
		}
	}
	return found, n, nil
}
