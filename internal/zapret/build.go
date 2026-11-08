package zapret

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Files of the winws2 folder the command line names: the zapret2 Lua
// libraries and the fake payloads (the folder HyRoute stages, runtimefiles).
var (
	LuaFiles  = []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"}
	BlobFiles = map[string]string{ // blob name -> file
		"google_tls":  "tls_clienthello_www_google_com.bin",
		"quic_google": "quic_initial_www_google_com.bin",
		// A site on TSPU's white list: a ClientHello naming it keeps the
		// connection out of the "16-20 KB" cut of hosting and CDN
		// addresses (Flowseal does the same with 4pda.to's).
		"vk_tls": "tls_clienthello_vk_com.bin",
	}
)

// Ports.
const (
	discordMediaTCP = "2053,2083,2087,2096,8443"
	discordVoiceUDP = "19294-19344,50000-50100"
)

// List files (in BuildConfig.Lists).
const (
	ListYouTube  = "youtube.txt"
	ListDiscord  = "discord.txt"
	ListSites    = "sites.txt"
	ListExcluded = "exclude-ip.txt" // HyRoute's servers: never touched
)

// BuildConfig is what a command line is built from.
type BuildConfig struct {
	// Dir holds winws2.exe with lua\ and blobs\ (absolute).
	Dir string
	// Lists holds the list files (absolute), written by WriteLists.
	Lists string
	// Plans: the targets processed (a target absent is not).
	Plans map[Target]Plan
	// Filter narrows the packets winws2 takes (--wf-raw-filter, ANDed with
	// its own): ProbeExclude for the user's bypass, ProbeOnly for a tester.
	Filter string
}

// decoy is the host a hostfakesplit puts in place of the target's.
func decoy(t Target) string {
	switch t {
	case YouTube:
		return "google.com"
	case Discord:
		return "discord.com"
	}
	return "ya.ru"
}

// Build returns winws2's arguments. Every profile skips HyRoute's servers
// (ListExcluded): a REALITY server may present the name of a site from the
// lists, and a desync of its connection would break the tunnel.
func Build(c BuildConfig) ([]string, error) {
	if len(c.Plans) == 0 {
		return nil, errors.New("нечего обходить: не выбрано ни одного сервиса")
	}
	if !filepath.IsAbs(c.Dir) || !filepath.IsAbs(c.Lists) {
		return nil, errors.New("zapret: пути должны быть полными")
	}
	list := func(name string) string { return filepath.Join(c.Lists, name) }
	circular := false
	tcpOut, udpOut := []string{"80", "443"}, []string{}
	for t, p := range c.Plans {
		if len(p.Methods) == 0 {
			return nil, fmt.Errorf("zapret: нет методов для %s", t)
		}
		for _, id := range p.Methods {
			if _, ok := FindMethod(id); !ok {
				return nil, fmt.Errorf("zapret: неизвестный метод %q", id)
			}
		}
		circular = circular || p.Circular && len(p.Methods) > 1
		udpOut = appendNew(udpOut, "443")
		if t == Discord {
			tcpOut = appendNew(tcpOut, discordMediaTCP)
			udpOut = appendNew(udpOut, discordVoiceUDP)
		}
	}
	args := []string{
		"--wf-tcp-out=" + strings.Join(tcpOut, ","),
		"--wf-udp-out=" + strings.Join(udpOut, ","),
	}
	if circular {
		// The failure detector reads the answers.
		args = append(args, "--wf-tcp-in=80,443")
	}
	libs := LuaFiles[:2]
	if circular {
		libs = LuaFiles
	}
	for _, f := range libs {
		args = append(args, "--lua-init=@"+filepath.Join(c.Dir, "lua", f))
	}
	for _, name := range []string{"google_tls", "quic_google", "vk_tls"} {
		args = append(args, "--blob="+name+":@"+filepath.Join(c.Dir, "blobs", BlobFiles[name]))
	}
	args = append(args, fakeArgs(c.Lists, c.Plans)...)
	if c.Filter != "" {
		args = append(args, "--wf-raw-filter="+c.Filter)
	}
	args = append(args, "--lua-gc=60")

	var profiles [][]string
	exclude := "--ipset-exclude=" + list(ListExcluded)
	for _, t := range Targets {
		p, on := c.Plans[t]
		if !on {
			continue
		}
		hostlist := "--hostlist=" + list(map[Target]string{YouTube: ListYouTube, Discord: ListDiscord, Sites: ListSites}[t])
		if t == Discord {
			profiles = append(profiles,
				[]string{"--comment=Discord voice", "--filter-udp=" + discordVoiceUDP, "--filter-l7=discord,stun", exclude,
					"--payload=discord_ip_discovery", "--out-range=-d10", "--lua-desync=fake:blob=quic_google"},
				tlsProfile("Discord media", t, discordMediaTCP, "tls", hostlist, exclude, p))
		}
		l7 := "tls"
		if t == Sites {
			l7 = "tls,http"
		}
		profiles = append(profiles,
			tlsProfile(TargetName(t), t, "80,443", l7, hostlist, exclude, p),
			[]string{"--comment=" + TargetName(t) + " QUIC", "--filter-udp=443", "--filter-l7=quic", hostlist, exclude,
				"--payload=quic_initial", "--out-range=-d10", "--lua-desync=fake:blob=quic_google"})
	}
	for i, p := range profiles {
		if i > 0 {
			args = append(args, "--new")
		}
		args = append(args, p...)
	}
	return args, nil
}

// tlsProfile is a TCP profile of a target: its plan's methods, rotated by
// circular when the plan says so.
func tlsProfile(comment string, t Target, ports, l7, hostlist, exclude string, p Plan) []string {
	out := []string{"--comment=" + comment, "--filter-tcp=" + ports, "--filter-l7=" + l7, hostlist, exclude}
	payload := "--payload=tls_client_hello"
	if strings.Contains(l7, "http") {
		payload += ",http_req"
	}
	if p.Circular && len(p.Methods) > 1 {
		// As in zapret2's manual: circular sees every packet of the first
		// bytes both ways (a --payload filter before it would hide the
		// DPI's RST and the answers that reset its failure count), the
		// methods only the ClientHello. nld=2: one count per domain
		// (googlevideo.com), not per one of its hundreds of servers; own
		// sites keep one per host (nld=2 of example.co.uk is co.uk).
		circular := "--lua-desync=circular:fails=3:retrans=2"
		if t != Sites {
			circular += ":nld=2"
		}
		out = append(out, "--out-range=-s34228", "--in-range=-s5556", circular, "--in-range=x", payload)
		for n, id := range p.Methods {
			m, _ := FindMethod(id)
			for _, inst := range m.tcp {
				out = append(out, "--lua-desync="+fill(inst, t)+fmt.Sprintf(":strategy=%d", n+1))
			}
		}
		return out
	}
	m, _ := FindMethod(p.Methods[0])
	out = append(out, "--out-range=-d10", payload)
	for _, inst := range m.tcp {
		out = append(out, "--lua-desync="+fill(inst, t))
	}
	return out
}

// base is a path's file name, whatever its separators.
func base(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func fill(inst string, t Target) string { return strings.ReplaceAll(inst, "{host}", decoy(t)) }

func appendNew(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// CommandLine is args as one line for the UI (paths shortened to their
// file names, quoted when needed).
func CommandLine(args []string) string {
	var b strings.Builder
	b.WriteString("winws2.exe")
	for _, a := range args {
		if i := strings.LastIndex(a, "@"); i >= 0 {
			a = a[:i+1] + base(a[i+1:])
		} else if k, v, ok := strings.Cut(a, "="); ok && strings.ContainsAny(v, `\/`) {
			a = k + "=" + base(v)
		}
		if a == "--new" {
			b.WriteString(" \\\n  --new")
			continue
		}
		b.WriteString(" ")
		if strings.ContainsAny(a, " \"") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		b.WriteString(a)
	}
	return b.String()
}
