package zapret

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Domains of the built-in targets (subdomains included: winws2 matches
// them itself).
var (
	youTubeDomains = []string{
		"youtube.com", "youtu.be", "yt.be", "youtube-nocookie.com", "youtubekids.com",
		"googlevideo.com", "ytimg.com", "ggpht.com",
		"youtubei.googleapis.com", "youtube.googleapis.com", "yt3.googleusercontent.com",
		"wide-youtube.l.google.com",
	}
	discordDomains = []string{
		"discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net",
		"discordcdn.com", "discord.dev", "discord.co", "discord.gift", "discord.gifts",
		"discord.new", "discord.store", "discord.tools", "discord.design", "discordstatus.com",
		"discordsays.com", "discord-activities.com", "discordactivities.com", "discordmerch.com",
		"discordpartygames.com", "dis.gd",
	}
)

// Domains is a target's hostlist (Sites: the user's).
func Domains(t Target, sites []string) []string {
	switch t {
	case YouTube:
		return youTubeDomains
	case Discord:
		return discordDomains
	}
	return sites
}

// WriteLists writes the list files Build names into dir: the targets'
// domains and HyRoute's server addresses, which every profile skips. A
// file whose content is unchanged is left alone (winws2 rereads a list
// when it changes).
func WriteLists(dir string, sites []string, servers []netip.Addr) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ips := make([]string, 0, len(servers))
	for _, a := range servers {
		if a.IsValid() {
			ips = append(ips, a.Unmap().String())
		}
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)
	files := map[string][]string{
		ListYouTube:  youTubeDomains,
		ListDiscord:  discordDomains,
		ListSites:    sites,
		ListExcluded: ips,
	}
	for name, lines := range files {
		body := []byte("# HyRoute: файл пересоздаётся\n" + strings.Join(lines, "\n") + "\n")
		if len(lines) == 0 && name != ListExcluded {
			// An empty hostlist would make its profile match every host.
			body = []byte("# HyRoute: пусто\nexample.invalid\n")
		}
		path := filepath.Join(dir, name)
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, body) {
			continue
		}
		tmp := path + ".new"
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}
