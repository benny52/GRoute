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
	ListSitesNet = "sites-ip.txt"   // the own sites' addresses and networks
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
	// Sites: the own sites (Settings.Sites). Their addresses and networks
	// get profiles by address (--ipset), the names by name.
	Sites []string
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
	if circular {
		args = append(args, "--lua-init=@"+list(LuaFile))
	}
	args = append(args, fakeArgs(c.Lists, c.Plans)...)
	args = append(args, "--wf-raw-filter="+rawFilter(c.Filter, circular))
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
		// The own sites' addresses: by address, whatever name (or none,
		// or one ECH hides) the connection carries. A name list with
		// nothing in it is not built when there are addresses.
		names, nets := true, false
		if t == Sites {
			nets = len(SiteNets(c.Sites)) > 0
			names = len(SiteNames(c.Sites)) > 0 || !nets
		}
		if names {
			profiles = append(profiles,
				tlsProfile(TargetName(t), t, "80,443", l7, hostlist, exclude, p),
				[]string{"--comment=" + TargetName(t) + " QUIC", "--filter-udp=443", "--filter-l7=quic", hostlist, exclude,
					"--payload=quic_initial", "--out-range=-d10", "--lua-desync=fake:blob=quic_google"})
		}
		if nets {
			ipset := "--ipset=" + list(ListSitesNet)
			profiles = append(profiles,
				tlsProfile("Свои адреса", t, "80,443", l7, ipset, exclude, p),
				[]string{"--comment=Свои адреса QUIC", "--filter-udp=443", "--filter-l7=quic", ipset, exclude,
					"--payload=quic_initial", "--out-range=-d10", "--lua-desync=fake:blob=quic_google"})
		}
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
		circular := "--lua-desync=circular:fails=3:retrans=2:success_detector=hyroute_success"
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

// Packets winws2 need not see, which WinDivert would otherwise carry to it
// and back (a round trip each, the CPU of every download):
//   - QUIC (UDP 443) after its first, long-header packets: the profiles
//     act on the Initial alone, but a QUIC download sends acknowledgements
//     all along;
//   - with the circular orchestrator, which reads the answers: any
//     answer's data but its start — a TLS server's first record (0x16) or
//     an HTTP answer. winws2 always takes SYN, FIN and RST itself, and an
//     HTTP redirect is an HTTP answer. hyroute_success (LuaFile) takes the
//     TLS server's first record as the sign that the connection went
//     through, which the default detector found in the bytes after it.
const (
	quicLean    = "(inbound or !udp or udp.DstPort != 443 or (udp.PayloadLength > 0 and udp.Payload[0] >= 0xC0))"
	inboundLean = "(outbound or !tcp or tcp.PayloadLength == 0 or tcp.Payload[0] == 0x16 or (tcp.PayloadLength >= 4 and tcp.Payload32[0] == 0x48545450))"
)

// rawFilter is the --wf-raw-filter (only one is allowed): the slots'
// filter and the lean parts.
func rawFilter(slots string, circular bool) string {
	parts := []string{quicLean}
	if circular {
		parts = append(parts, inboundLean)
	}
	if slots != "" {
		parts = append([]string{"(" + slots + ")"}, parts...)
	}
	return strings.Join(parts, " and ")
}

// LuaFile is HyRoute's own Lua for winws2, written into the lists folder
// (WriteLists): the circular orchestrator's success detector for the
// packets rawFilter lets through.
const LuaFile = "hyroute.lua"

const luaSource = `-- HyRoute: the success detector of the circular orchestrator.
-- HyRoute lets an answer reach winws2 only at its start (a TLS server's
-- first record, an HTTP answer), so the default detector, which waits for
-- the answer's later bytes, would never see one. A TLS server's first
-- record, or an HTTP 2xx, means the connection got through. Anything else
-- (an HTTP redirect to a stub page among them) is left to the default
-- detectors.
function hyroute_success(desync, crec)
	if desync.dis.tcp and not desync.outgoing and desync.dis.payload and #desync.dis.payload > 0 then
		local p = desync.dis.payload
		if string.byte(p, 1) == 0x16 then
			return true
		end
		if #p >= 10 and string.sub(p, 1, 7) == "HTTP/1." and string.sub(p, 10, 10) == "2" then
			return true
		end
	end
	return standard_success_detector(desync, crec)
end
`
