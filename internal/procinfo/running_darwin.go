//go:build darwin

package procinfo

import (
	"path/filepath"
	"sort"
	"strings"
)

// ListRunning lists the programs running on this Mac, one entry per
// executable, for the rule editor's suggestions. Programs inside an
// application bundle (/Applications/X.app/...) count as windowed; the
// system's own (/System, /usr, /sbin, /bin) as system.
func ListRunning() []Running {
	byPath := map[string]*Running{}
	for _, e := range snapshot() {
		if e.PID == 0 {
			continue
		}
		path := execPath(e.PID)
		if path == "" || !filepath.IsAbs(path) {
			continue
		}
		if r := byPath[path]; r != nil {
			r.Count++
			continue
		}
		r := &Running{Name: filepath.Base(path), Path: path, Count: 1}
		if i := strings.Index(path, ".app/"); i > 0 {
			r.Description = strings.TrimSuffix(filepath.Base(path[:i+4]), ".app")
			r.Windowed = true
		}
		for _, sys := range []string{"/System/", "/usr/", "/sbin/", "/bin/", "/Library/Apple/"} {
			if strings.HasPrefix(path, sys) {
				r.System = true
			}
		}
		byPath[path] = r
	}
	out := make([]Running, 0, len(byPath))
	for _, r := range byPath {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}
