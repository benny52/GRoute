package zapret

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
)

// The strategy generator. A Strategy is a desync recipe put together from
// the parts zapret2's blockcheck2 combines (blockcheck2.d/standard): a fake
// ClientHello and how it is made to die before the server (the fooling),
// a split of the real ClientHello and where. Every field takes only values
// from the lists below, so a generated strategy (kept in zapret.json, which
// the user may edit) never puts text of its own on winws2's command line:
// Parse refuses anything else.
type Strategy struct {
	Fake    string // fake payload: a key of fakeBlobs ("" = no fake)
	Fool    string // a key of foolings: how fakes (and faked parts) die
	TTL     int    // with Fool "ttl": the TTL; with "autottl": the delta
	Repeats int    // fakes sent (1…12)
	Mod     bool   // the fake with random fields (tls_mod=rnd,dupsid)
	Split   string // a key of splits ("" = the real ClientHello whole)
	Pos     string // where to split: a key of positions
	Seqovl  int    // multisplit: bytes of pattern before the first part
	Pattern string // seqovl pattern: a key of fakeBlobs (not zero)
	Host    string // hostfakesplit: a name of splitHosts
	Lead    bool   // four zero bytes go as a fake before the fake
	Clone   string // the fake is the real ClientHello under this name (of splitHosts); Fake when it cannot be made
	IPID    bool   // every packet of the method with IP ID 0
}

// GenPrefix starts the ID of a generated strategy (library methods have
// plain IDs).
const GenPrefix = "g:"

// fakeBlobs: the fake payloads, by the blob name winws2 knows them as.
// google and vk come with zapret2; the white-listed names' ClientHellos are
// made by HyRoute (fakes.go); zero is 64 zero bytes.
var fakeBlobs = map[string]string{
	"google": "google_tls",
	"vk":     "vk_tls",
	"zero":   "0x" + strings.Repeat("00", 64),
}

// foolings: how a fake dies before reaching the server while DPI takes it.
var foolings = map[string]string{
	"ts":     "tcp_ts=-1000",
	"md5":    "tcp_ts=-1000:tcp_md5",
	"badsum": "badsum",
	"seq":    "tcp_seq=-3000",
	"ack":    "tcp_ack=-66000:tcp_ts_up",
	// winws's badseq as Flowseal's presets set it: SEQ moved by its
	// --dpi-desync-badseq-increment (-10000 when not given, 2, 1000,
	// 10000000) and ACK by -66000, which makes the server drop the fake.
	"badseq":    "tcp_seq=-10000:tcp_ack=-66000",
	"badseq2":   "tcp_seq=2:tcp_ack=-66000",
	"badseq1k":  "tcp_seq=1000:tcp_ack=-66000",
	"badseqfar": "tcp_seq=10000000:tcp_ack=-66000",
	// winws's ts (by its default -600000) where it works: an old timestamp
	// when the connection has TCP timestamps (Windows sends them only once
	// the user turned them on, as Flowseal's service.bat does), else a TCP
	// MD5 option (hyroute_ts of LuaFile).
	"tsauto":  "fool=hyroute_ts",
	"ttl":     "ip_ttl=%d:ip6_ttl=%d",
	"autottl": "ip_autottl=-%d,3-20:ip6_autottl=-%d,3-20",
}

// activeFoolings are the ones the generator makes. On Windows tcp_ts
// spoils nothing (no TCP timestamps) and a badsum packet does not leave
// the machine (Windows CI: the fakes reached example.com and broke the
// handshake); stored strategies with them still parse.
var activeFoolings = []string{"md5", "tsauto", "seq", "ack", "badseq", "badseq2", "badseq1k", "badseqfar", "ttl", "autottl"}

var foolingNames = map[string]string{
	"ts": "старая метка времени", "md5": "TCP MD5", "badsum": "битая сумма", "seq": "сдвиг SEQ",
	"ack": "сдвиг ACK", "ttl": "малый TTL", "autottl": "TTL по расстоянию",
	"badseq": "сдвиг SEQ и ACK", "badseq2": "сдвиг SEQ на 2 и ACK", "badseq1k": "сдвиг SEQ на 1000 и ACK",
	"badseqfar": "сдвиг SEQ на 10 млн и ACK", "tsauto": "старая метка времени или TCP MD5",
}

// splits of the real ClientHello. faked* and hostfakesplit send fakes of
// their own and need a fooling.
var splits = []string{"multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"}

var splitNames = map[string]string{
	"multisplit": "разрез", "multidisorder": "перестановка частей", "fakedsplit": "разрез с фейковыми частями",
	"fakeddisorder": "перестановка с фейковыми частями", "hostfakesplit": "подмена имени в части",
}

// positions: zapret2 position markers. Lists are for multisplit and
// multidisorder only.
var positions = []string{"1", "2", "midsld", "sniext+1", "host+1", "1,midsld", "2,midsld", "1,sniext+1", "2,sniext+1",
	"3,sniext+1", "sniext+1,midsld", posSeven}

// posSeven: the name cut in seven places (kinlay0's presets for zapret2).
const posSeven = "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"

var positionNames = map[string]string{
	"1": "после 1-го байта", "2": "после 2-го байта", "midsld": "на середине домена", "sniext+1": "в начале SNI",
	"host+1": "в начале имени", "1,midsld": "в двух местах", "2,midsld": "в двух местах", "1,sniext+1": "в двух местах",
	"2,sniext+1": "в двух местах", "3,sniext+1": "в двух местах", "sniext+1,midsld": "в двух местах",
	posSeven: "в семи местах",
}

// seqovls: 1 is an overlap of one zero byte (no pattern), the others of a
// ClientHello (a pattern): Flowseal's are the lengths of its fakes.
var seqovls = []int{1, 336, 568, 652, 664, 679, 681}

// splitHosts: the names a hostfakesplit may put in place of the site's:
// the white-listed ones and Flowseal's for Google's names.
var splitHosts = append([]string{"www.google.com"}, WhiteNames...)

// fakeName is a fake for the UI.
func fakeName(k string) string {
	switch k {
	case "google":
		return "google.com"
	case "vk":
		return "vk.com"
	case "zero":
		return "нули"
	}
	if w, ok := whiteByKey(k); ok {
		return w
	}
	return k
}

// valid reports whether s is a strategy the generator may build.
func (s Strategy) valid() bool {
	fakeOK := func(k string) bool { _, ok := fakeBlobs[k]; _, w := whiteByKey(k); return ok || w }
	if s.Fake != "" && !fakeOK(s.Fake) || s.Pattern != "" && (s.Pattern == "zero" || !fakeOK(s.Pattern)) {
		return false
	}
	if _, ok := foolings[s.Fool]; s.Fool != "" && !ok {
		return false
	}
	switch s.Fool {
	case "ttl":
		if s.TTL < 1 || s.TTL > 12 {
			return false
		}
	case "autottl":
		if s.TTL < 1 || s.TTL > 4 {
			return false
		}
	default:
		if s.TTL != 0 {
			return false
		}
	}
	needFool := s.Fake != "" || s.Split == "fakedsplit" || s.Split == "fakeddisorder" || s.Split == "hostfakesplit"
	if needFool != (s.Fool != "") || needFool != (s.Repeats > 0) || s.Repeats > 12 {
		return false
	}
	if (s.Mod || s.Lead || s.Clone != "") && (s.Fake == "" || s.Fake == "zero") {
		return false
	}
	if s.Clone != "" && !slices.Contains(splitHosts, s.Clone) {
		return false
	}
	switch s.Split {
	case "":
		return s.Fake != "" && s.Pos == "" && s.Seqovl == 0 && s.Pattern == "" && s.Host == ""
	case "multisplit":
		if s.Seqovl != 0 && !slices.Contains(seqovls, s.Seqovl) || (s.Seqovl > 1) != (s.Pattern != "") {
			return false
		}
		return slices.Contains(positions, s.Pos) && s.Host == ""
	case "multidisorder":
		return slices.Contains(positions, s.Pos) && s.Seqovl == 0 && s.Pattern == "" && s.Host == ""
	case "fakedsplit", "fakeddisorder":
		return slices.Contains(positions, s.Pos) && !strings.Contains(s.Pos, ",") && s.Seqovl == 0 && s.Host == ""
	case "hostfakesplit":
		return s.Pos == "" && s.Seqovl == 0 && s.Pattern == "" && slices.Contains(splitHosts, s.Host)
	}
	return false
}

// ID encodes s; Parse reads it back.
func (s Strategy) ID() string {
	var p []string
	add := func(k, v string) {
		if v != "" && v != "0" && v != "false" {
			p = append(p, k+"="+v)
		}
	}
	add("f", s.Fake)
	add("o", s.Fool)
	add("t", strconv.Itoa(s.TTL))
	add("r", strconv.Itoa(s.Repeats))
	add("m", strconv.FormatBool(s.Mod))
	add("s", s.Split)
	add("p", s.Pos)
	add("q", strconv.Itoa(s.Seqovl))
	add("n", s.Pattern)
	add("h", s.Host)
	add("l", strconv.FormatBool(s.Lead))
	add("c", s.Clone)
	add("i", strconv.FormatBool(s.IPID))
	return GenPrefix + strings.Join(p, ";")
}

// ParseStrategy reads a generated strategy's ID; ok is false for anything
// the generator would not build.
func ParseStrategy(id string) (s Strategy, ok bool) {
	rest, found := strings.CutPrefix(id, GenPrefix)
	if !found || rest == "" || len(rest) > 200 {
		return s, false
	}
	seen := map[string]bool{}
	for _, kv := range strings.Split(rest, ";") {
		k, v, cut := strings.Cut(kv, "=")
		if !cut || v == "" || seen[k] {
			return s, false
		}
		seen[k] = true
		num := func() (int, bool) {
			n, err := strconv.Atoi(v)
			return n, err == nil && strconv.Itoa(n) == v
		}
		var nok bool
		switch k {
		case "f":
			s.Fake, nok = v, true
		case "o":
			s.Fool, nok = v, true
		case "t":
			s.TTL, nok = num()
		case "r":
			s.Repeats, nok = num()
		case "m":
			s.Mod, nok = true, v == "true"
		case "s":
			s.Split, nok = v, true
		case "p":
			s.Pos, nok = v, true
		case "q":
			s.Seqovl, nok = num()
		case "n":
			s.Pattern, nok = v, true
		case "h":
			s.Host, nok = v, true
		case "l":
			s.Lead, nok = true, v == "true"
		case "c":
			s.Clone, nok = v, true
		case "i":
			s.IPID, nok = true, v == "true"
		}
		if !nok {
			return Strategy{}, false
		}
	}
	if !s.valid() || s.ID() != id {
		return Strategy{}, false
	}
	return s, true
}

func (s Strategy) fooling() string {
	f := foolings[s.Fool]
	if strings.Contains(f, "%d") {
		f = fmt.Sprintf(f, s.TTL, s.TTL)
	}
	return f
}

func blobOf(k string) string {
	if b, ok := fakeBlobs[k]; ok {
		return b
	}
	return whiteBlob(k)
}

// cloneBlob is the blob a strategy's copy of the real ClientHello is kept as.
const cloneBlob = "ch_clone"

// instances are the --lua-desync values of s.
func (s Strategy) instances() []string {
	var out []string
	if s.Lead {
		out = append(out, fmt.Sprintf("fake:blob=0x00000000:%s:repeats=%d", s.fooling(), s.Repeats))
	}
	if s.Fake != "" {
		blob := blobOf(s.Fake)
		if s.Clone != "" {
			// zapret2 puts the name into a copy of the ClientHello it is
			// about to send (the browser's own fingerprint) and keeps it as
			// a blob of this connection.
			out = append(out, fmt.Sprintf("tls_client_hello_clone:blob=%s:fallback=%s:sni_del:sni_first=%s:sni_snt_new=0", cloneBlob, blob, s.Clone))
			blob = cloneBlob
		}
		f := fmt.Sprintf("fake:blob=%s:%s:repeats=%d", blob, s.fooling(), s.Repeats)
		if s.Mod {
			f += ":tls_mod=rnd,dupsid"
		}
		out = append(out, f)
	}
	switch s.Split {
	case "multisplit":
		f := "multisplit:pos=" + s.Pos
		if s.Seqovl > 0 {
			f += fmt.Sprintf(":seqovl=%d", s.Seqovl)
			if s.Pattern != "" {
				f += ":seqovl_pattern=" + blobOf(s.Pattern)
			}
		}
		out = append(out, f)
	case "multidisorder":
		out = append(out, "multidisorder:pos="+s.Pos)
	case "fakedsplit", "fakeddisorder":
		f := fmt.Sprintf("%s:pos=%s:%s:repeats=%d", s.Split, s.Pos, s.fooling(), s.Repeats)
		if s.Pattern != "" {
			f += ":pattern=" + blobOf(s.Pattern)
		}
		out = append(out, f)
	case "hostfakesplit":
		out = append(out, fmt.Sprintf("hostfakesplit:host=%s:%s:repeats=%d", s.Host, s.fooling(), s.Repeats))
	}
	if s.IPID {
		for i := range out {
			if !strings.HasPrefix(out[i], "tls_client_hello_clone:") { // it sends nothing
				out[i] += ":ip_id=zero"
			}
		}
	}
	return out
}

// blobs are the HyRoute-made fakes s uses (their keys).
func (s Strategy) whiteBlobs() []string {
	var out []string
	for _, k := range []string{s.Fake, s.Pattern} {
		if _, ok := whiteByKey(k); ok && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// Name says what s does, for the UI.
func (s Strategy) Name() string {
	var p []string
	if s.Fake != "" {
		f := "фейк " + fakeName(s.Fake)
		if s.Clone != "" {
			f = "фейк-копия настоящего начала под именем " + s.Clone
		}
		if s.Mod {
			f += " со случайными полями"
		}
		if s.Lead {
			f = "нули и " + f
		}
		p = append(p, fmt.Sprintf("%s (%s, ×%d)", f, foolName(s), s.Repeats))
	}
	switch s.Split {
	case "":
	case "multisplit":
		f := splitNames[s.Split] + " " + positionNames[s.Pos]
		if s.Seqovl == 1 {
			f += " с перекрытием в 1 байт"
		} else if s.Seqovl > 0 {
			f += " с перекрытием " + fakeName(s.Pattern)
		}
		p = append(p, f)
	case "hostfakesplit":
		f := splitNames[s.Split] + " на " + s.Host
		if s.Fake == "" {
			f += fmt.Sprintf(" (%s)", foolName(s))
		}
		p = append(p, f)
	default:
		f := splitNames[s.Split] + " " + positionNames[s.Pos]
		if s.Fake == "" {
			f += fmt.Sprintf(" (%s)", foolName(s))
		}
		p = append(p, f)
	}
	n := strings.Join(p, " + ")
	if s.IPID {
		n += ", IP ID 0"
	}
	return strings.ToUpper(n[:2]) + n[2:]
}

func foolName(s Strategy) string {
	n := foolingNames[s.Fool]
	if s.Fool == "ttl" {
		n += " " + strconv.Itoa(s.TTL)
	}
	return n
}

// Neighbors are the strategies one change away from s: another fooling,
// fake, position, overlap, repeat count. The generator tries them around
// what works, for a faster one and for spares.
func Neighbors(s Strategy) []Strategy {
	var out []Strategy
	try := func(n Strategy) {
		if n.valid() && n != s && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	ipid := s
	ipid.IPID = !ipid.IPID
	try(ipid)
	if s.Fool != "" {
		for _, f := range activeFoolings {
			n := s
			n.Fool, n.TTL = f, 0
			switch f {
			case "ttl":
				for _, t := range []int{3, 5, 8} {
					n.TTL = t
					try(n)
				}
				continue
			case "autottl":
				n.TTL = 2
			}
			try(n)
		}
		for _, r := range []int{2, 6, 11} {
			n := s
			n.Repeats = r
			try(n)
		}
	}
	for _, f := range fakeKeys() {
		if s.Fake != "" {
			n := s
			n.Fake = f
			n.Mod = n.Mod && f != "zero"
			try(n)
		}
		if s.Pattern != "" && f != "zero" {
			n := s
			n.Pattern = f
			try(n)
		}
	}
	if s.Pos != "" {
		for _, p := range positions {
			n := s
			n.Pos = p
			try(n)
		}
	}
	if s.Split == "multisplit" {
		for _, q := range seqovls {
			n := s
			n.Seqovl = q
			if q == 1 {
				n.Pattern = ""
			} else if n.Pattern == "" {
				n.Pattern = "vk"
			}
			try(n)
		}
	}
	if s.Split == "hostfakesplit" {
		for _, h := range splitHosts {
			n := s
			n.Host = h
			try(n)
		}
	}
	if s.Fake != "" && s.Fake != "zero" {
		n := s
		n.Mod = !n.Mod
		try(n)
		n = s
		n.Lead = !n.Lead
		try(n)
		for _, c := range append([]string{""}, splitHosts...) {
			n = s
			n.Clone = c
			try(n)
		}
	}
	return out
}

func fakeKeys() []string {
	out := []string{"google", "zero"}
	for _, w := range WhiteNames {
		out = append(out, whiteKey(w)) // vk.com's is "vk"
	}
	return out
}

// Broad is a spread of n strategies over the whole space, for when nothing
// of the library worked: every family, fooling and fake. seed makes it
// repeatable (tests); the pick seeds it at random.
func Broad(n int, seed uint64) []Strategy {
	rnd := rand.New(rand.NewPCG(seed, seed^0x5eed))
	pick := func(xs []string) string { return xs[rnd.IntN(len(xs))] }
	fools := activeFoolings
	fakes := fakeKeys()
	patterns := slices.DeleteFunc(slices.Clone(fakes), func(k string) bool { return k == "zero" })
	var out []Strategy
	for tries := 0; len(out) < n && tries < n*50; tries++ {
		s := Strategy{}
		family := tries % 6                        // every family in turn
		withFake := family == 5 || rnd.IntN(3) > 0 // a fake in front, mostly
		if withFake {
			s.Fake = pick(fakes)
			s.Mod = s.Fake != "zero" && rnd.IntN(4) == 0
			s.Lead = s.Fake != "zero" && rnd.IntN(8) == 0
			if s.Fake != "zero" && rnd.IntN(5) == 0 {
				s.Clone = pick(splitHosts)
			}
		}
		s.IPID = rnd.IntN(3) == 0
		switch family {
		case 0, 1:
			s.Split, s.Pos = "multisplit", pick(positions)
			if family == 0 || rnd.IntN(2) == 0 {
				if s.Seqovl = seqovls[rnd.IntN(len(seqovls))]; s.Seqovl > 1 {
					s.Pattern = pick(patterns)
				}
			}
		case 2:
			s.Split, s.Pos = "multidisorder", pick(positions)
		case 3:
			s.Split = pick([]string{"fakedsplit", "fakeddisorder"})
			s.Pos = pick([]string{"1", "2", "midsld", "sniext+1", "host+1"})
		case 4:
			s.Split, s.Host = "hostfakesplit", pick(splitHosts)
		case 5: // a fake alone
		}
		if s.Fake != "" || s.Split == "fakedsplit" || s.Split == "fakeddisorder" || s.Split == "hostfakesplit" {
			s.Fool = pick(fools)
			s.Repeats = []int{2, 4, 6, 8, 11}[rnd.IntN(5)]
			switch s.Fool {
			case "ttl":
				s.TTL = 2 + rnd.IntN(9)
			case "autottl":
				s.TTL = 1 + rnd.IntN(3)
			}
		}
		if s.valid() && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Known are the recipes for Google's names (list-google in general*.bat)
// of Flowseal's zapret-discord-youtube 1.10.4 and of kinlay0's
// zapret2-discord-youtube-strats that the library does not hold, in the
// generator's terms: their ts fooling is tsauto, badseq with an increment
// the badseq foolings, --ip-id=zero IPID. Some name max.ru or
// www.sferum.ru where the others name google.com (for a TSPU that knows the
// google.com fake). A pick tries them all when nothing opened a service,
// before the spread.
func Known() []Strategy {
	const g, max = "google", "w_max_ru"
	return []Strategy{
		{Split: "multisplit", Pos: "2", Seqovl: 652, Pattern: g, IPID: true},                                                    // ALT2
		{Split: "multisplit", Pos: "2,sniext+1", Seqovl: 679, Pattern: g, IPID: true},                                           // ALT7
		{Fake: g, Fool: "tsauto", Repeats: 6, IPID: true},                                                                       // ALT10
		{Fake: g, Fool: "tsauto", Repeats: 8, Split: "multisplit", Pos: "1", Seqovl: 681, Pattern: g, IPID: true},               // ALT11
		{Fake: g, Fool: "tsauto", Repeats: 6, Split: "fakedsplit", Pos: "2", IPID: true},                                        // ALT
		{Fool: "tsauto", Repeats: 1, Split: "hostfakesplit", Host: "www.google.com", IPID: true},                                // ALT12
		{Fool: "tsauto", Repeats: 4, Split: "hostfakesplit", Host: "www.google.com", IPID: true},                                // ALT9
		{Fake: g, Mod: true, Fool: "tsauto", Repeats: 1, Split: "hostfakesplit", Host: "www.google.com", IPID: true},            // ALT3
		{Fake: g, Fool: "badseq1k", Repeats: 6, Split: "multisplit", Pos: "2", IPID: true},                                      // ALT4
		{Fake: g, Fool: "badseq2", Repeats: 6, IPID: true},                                                                      // SIMPLE FAKE ALT
		{Fake: g, Mod: true, Fool: "badseq2", Repeats: 8, Split: "fakedsplit", Pos: "1", IPID: true},                            // FAKE TLS AUTO ALT
		{Fake: g, Mod: true, Fool: "badseqfar", Repeats: 8, Split: "multisplit", Pos: "1", Seqovl: 681, Pattern: g, IPID: true}, // FAKE TLS AUTO ALT2
		{Fake: g, Mod: true, Fool: "tsauto", Repeats: 8, Split: "multisplit", Pos: "1", Seqovl: 681, Pattern: g, IPID: true},    // FAKE TLS AUTO ALT3
		{Fake: g, Mod: true, Lead: true, Fool: "badseq", Repeats: 11, Split: "multidisorder", Pos: "1,midsld", IPID: true},      // FAKE TLS AUTO
		{Split: "multisplit", Pos: "1", Seqovl: 681, Pattern: max, IPID: true},
		{Fake: max, Fool: "tsauto", Repeats: 8, Split: "multisplit", Pos: "1", Seqovl: 681, Pattern: max, IPID: true},
		// kinlay0's.
		{Fake: g, Fool: "tsauto", Repeats: 6, Split: "multidisorder", Pos: "2,midsld", IPID: true},                                         // SIMPLE FAKE, DOUBLE FAKE
		{Split: "multidisorder", Pos: "2,midsld", IPID: true},                                                                              // EXPERIMENTAL TS
		{Fake: g, Fool: "tsauto", Repeats: 8, Split: "multisplit", Pos: "2", Seqovl: 681, Pattern: g, IPID: true},                          // ALT14
		{Split: "multidisorder", Pos: posSeven},                                                                                            // EXP1
		{Fake: g, Mod: true, Fool: "tsauto", Repeats: 6, Split: "multidisorder", Pos: posSeven},                                            // EXP2
		{Split: "multisplit", Pos: "3,sniext+1", Seqovl: 681, Pattern: g, IPID: true},                                                      // FAKE TLS AUTO ALT4
		{Fool: "tsauto", Repeats: 8, Split: "fakedsplit", Pos: "2", IPID: true},                                                            // FAKE TLS AUTO ALT6
		{Fake: g, Clone: "www.google.com", Fool: "tsauto", Repeats: 6, Split: "multisplit", Pos: "sniext+1,midsld", Seqovl: 1, IPID: true}, // EXP5
		{Fake: max, Clone: "max.ru", Fool: "tsauto", Repeats: 6, Split: "multisplit", Pos: "sniext+1,midsld", Seqovl: 1},                   // CIRCULAR, strategy 1
		{Fake: "w_www_sferum_ru", Fool: "tsauto", Repeats: 6, Split: "multisplit", Pos: "2", IPID: true},                                   // CIRCULAR, strategy 2
	}
}

// AsStrategy is a library method in the generator's terms (to vary it),
// when it is one.
func AsStrategy(id string) (Strategy, bool) {
	if s, ok := ParseStrategy(id); ok {
		return s, true
	}
	s, ok := libraryAsStrategy[id]
	return s, ok
}

// libraryAsStrategy: the library methods the generator can vary, as
// strategies (their parameters, not their exact text).
var libraryAsStrategy = map[string]Strategy{
	"fake-seqovl":      {Fake: "google", Fool: "autottl", TTL: 2, Repeats: 8, Split: "multisplit", Pos: "1,midsld", Seqovl: 681, Pattern: "google"},
	"fake-seqovl-mod":  {Fake: "google", Fool: "md5", Repeats: 8, Mod: true, Split: "multisplit", Pos: "1,midsld", Seqovl: 681, Pattern: "google"},
	"fake-md5-seqovl":  {Fake: "google", Fool: "md5", Repeats: 7, Split: "multisplit", Pos: "1,midsld", Seqovl: 681, Pattern: "google"},
	"fake":             {Fake: "google", Fool: "md5", Repeats: 7},
	"fake-disorder":    {Fake: "google", Fool: "md5", Repeats: 7, Split: "multidisorder", Pos: "1,midsld"},
	"fakedsplit":       {Fake: "google", Fool: "md5", Repeats: 7, Split: "fakedsplit", Pos: "2", Pattern: "google"},
	"seqovl-vk":        {Split: "multisplit", Pos: "1", Seqovl: 568, Pattern: "vk"},
	"fake-vk-seqovl":   {Fake: "vk", Fool: "md5", Repeats: 6, Split: "multisplit", Pos: "1,midsld", Seqovl: 681, Pattern: "vk"},
	"hostfakesplit-vk": {Fake: "vk", Fool: "md5", Repeats: 6, Split: "hostfakesplit", Host: "vk.com"},
}
