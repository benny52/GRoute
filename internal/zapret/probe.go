package zapret

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Checks are the addresses a target is checked with. DPI blocks in two
// ways: it stalls or resets the TLS handshake, or (TSPU) lets it and the
// first ~16 KB through and then freezes the connection. So each target has
// a page well over that (the main pages) and the check reads up to
// maxBody of every answer; googlevideo.com, where the video comes from,
// only serves small answers without a signed link but shows a blocked
// handshake.
func Checks(t Target, sites []string) []string {
	switch t {
	case YouTube:
		return []string{"https://www.youtube.com/", "https://redirector.googlevideo.com/report_mapping", "https://i.ytimg.com/generate_204"}
	case Discord:
		// The media: an official sticker (470 KB) on both CDN names, where
		// attachments and videos come from. Cloudflare's addresses get the
		// "16-20 KB" cut a small picture never shows.
		return []string{"https://discord.com/", "https://gateway.discord.gg/",
			"https://cdn.discordapp.com/stickers/781291131828699156.png", "https://media.discordapp.net/stickers/781291131828699156.png"}
	}
	// Names only: a bare address has no certificate of its own to check
	// against.
	var out []string
	for _, s := range SiteNames(sites) {
		if len(out) == 5 {
			break // the first few say enough
		}
		out = append(out, "https://"+s+"/")
	}
	return out
}

// CheckTimeout bounds one address's check.
var CheckTimeout = 8 * time.Second

// maxBody: how much of an answer the check reads. Past the ~16 KB after
// which TSPU freezes a connection; a shorter answer is read to its end.
const maxBody = 64 << 10

// Passes: a target counts as open only when every address answered this
// many times in a row (a method that works now and then is no use).
const Passes = 2

// Probe ports. The checks connect from fixed local port ranges, one per
// slot: slot 0 checks without any bypass, slot i (1…) belongs to the
// winws2 that tries method i. The bypass that runs for the user skips the
// whole range (ProbeExclude), so a pick runs next to it without stopping
// it, and all methods are tried at once. The range lies below Windows'
// dynamic ports (49152-65535).
const (
	ProbePortBase = 30000
	ProbeSlotSize = 150
	ProbeSlots    = 1 + 12
)

// ProbeSlot is the local port range of slot i.
func ProbeSlot(i int) (lo, hi int) {
	lo = ProbePortBase + i*ProbeSlotSize
	return lo, lo + ProbeSlotSize - 1
}

// portsFilter is a WinDivert filter for the packets of a local port range,
// both ways.
func portsFilter(lo, hi int) string {
	return fmt.Sprintf("(outbound and tcp.SrcPort >= %d and tcp.SrcPort <= %d) or (inbound and tcp.DstPort >= %d and tcp.DstPort <= %d)", lo, hi, lo, hi)
}

// ProbeExclude keeps the probes' packets from the bypass the user runs:
// TCP with neither port in the range (a probe's local port is the source
// going out and the destination coming in; the other side is 80, 443…).
// WinDivert refuses a negated compound like "not (a or b)" ("The parameter
// is incorrect"), so the filter only negates "tcp", as winws2's own do.
func ProbeExclude() string {
	lo, _ := ProbeSlot(0)
	_, hi := ProbeSlot(ProbeSlots - 1)
	return fmt.Sprintf("!tcp or ((tcp.SrcPort < %d or tcp.SrcPort > %d) and (tcp.DstPort < %d or tcp.DstPort > %d))", lo, hi, lo, hi)
}

// ProbeOnly limits a tester's winws2 to the probes of slot i.
func ProbeOnly(i int) string {
	lo, hi := ProbeSlot(i)
	return portsFilter(lo, hi)
}

// Kind is where a check broke: it says whether a bypass can help.
type Kind string

const (
	KindDNS      Kind = "dns"       // the name does not resolve
	KindDNSStub  Kind = "dns-stub"  // it resolves to a local or reserved address: the provider's stub
	KindIP       Kind = "ip"        // the address does not take connections: blocked by IP (or down)
	KindCert     Kind = "cert"      // someone else's certificate answered
	KindTLS      Kind = "tls"       // the handshake is reset or not answered: DPI on the site's name
	KindFreeze   Kind = "freeze"    // the connection dies after the first kilobytes (TSPU)
	KindNoAnswer Kind = "no-answer" // the server answered with an error
)

// severity orders the kinds: the earliest in a connection explains most.
var severity = map[Kind]int{KindDNSStub: 0, KindDNS: 1, KindIP: 2, KindCert: 3, KindTLS: 4, KindFreeze: 5, KindNoAnswer: 6}

// Bypassable: a method of winws2 can open what broke this way.
func (k Kind) Bypassable() bool { return k == KindTLS || k == KindFreeze }

// Explain says in a few words what a kind means for the user.
func (k Kind) Explain() string {
	switch k {
	case KindDNS:
		return "имя сайта не находится (DNS)"
	case KindDNSStub:
		return "провайдер подменяет адрес сайта (DNS)"
	case KindIP:
		return "сайт заблокирован по адресу: соединение не устанавливается"
	case KindCert:
		return "вместо сайта отвечает чужой сервер (подмена сертификата)"
	case KindTLS:
		return "провайдер сбрасывает соединение по имени сайта (DPI)"
	case KindFreeze:
		return "соединение замирает после первых килобайт (ТСПУ)"
	case KindNoAnswer:
		return "сайт отвечает ошибкой"
	}
	return ""
}

// Failure is one address that failed.
type Failure struct {
	Host string `json:"host"`
	Kind Kind   `json:"kind"`
	Text string `json:"text"` // what happened, in Russian
}

func (f Failure) String() string { return f.Host + ": " + f.Text }

// Result of checking a target.
type Result struct {
	OK      bool
	Failed  []Failure
	Elapsed time.Duration // the slowest address, averaged over the passes
}

// Diagnosis is the failure that explains most (the zero Failure when
// the target passed).
func (r Result) Diagnosis() Failure {
	var worst Failure
	for i, f := range r.Failed {
		if i == 0 || severity[f.Kind] < severity[worst.Kind] {
			worst = f
		}
	}
	return worst
}

// Bypassable: every failure is one a method can open.
func (r Result) Bypassable() bool {
	for _, f := range r.Failed {
		if !f.Kind.Bypassable() {
			return false
		}
	}
	return true
}

// Prober checks addresses from the local ports of one slot, with a
// ClientHello like Chrome's: DPI may treat a Go program's handshake
// differently from a browser's.
type Prober struct {
	Slot int
	// Test hooks: Resolve replaces DNS (no stub check then), Roots the
	// system's root certificates.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Roots   *x509.CertPool
}

// slotNext rotates the ports of each slot, across picks too: a port just
// used sits in TIME_WAIT.
var slotNext [ProbeSlots]atomic.Uint32

func (p *Prober) port() int {
	lo, _ := ProbeSlot(p.Slot)
	return lo + int(slotNext[p.Slot].Add(1)%ProbeSlotSize)
}

// Check checks every address of urls at once, Passes times. The target
// works when every address answers every time.
func (p *Prober) Check(ctx context.Context, urls []string) Result {
	res := Result{OK: len(urls) > 0}
	var total time.Duration
	for pass := 0; pass < Passes && res.OK; pass++ {
		var mu sync.Mutex
		var wg sync.WaitGroup
		var slowest time.Duration
		for _, u := range urls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				f := p.checkOne(ctx, u)
				d := time.Since(start)
				mu.Lock()
				defer mu.Unlock()
				slowest = max(slowest, d)
				if f != nil {
					res.OK = false
					res.Failed = append(res.Failed, *f)
				}
			}()
		}
		wg.Wait()
		total += slowest
		res.Elapsed = total / time.Duration(pass+1)
	}
	return res
}

// countConn counts the bytes read from the network (TLS included).
type countConn struct {
	net.Conn
	n atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n.Add(int64(n))
	return n, err
}

func (p *Prober) checkOne(ctx context.Context, rawURL string) *Failure {
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return &Failure{Host: rawURL, Kind: KindNoAnswer, Text: err.Error()}
	}
	host, port := req.URL.Hostname(), req.URL.Port()
	if port == "" {
		port = "443"
	}
	fail := func(k Kind, text string) *Failure { return &Failure{Host: host, Kind: k, Text: text} }

	// The name.
	var addrs []netip.Addr
	if p.Resolve != nil {
		addrs, err = p.Resolve(ctx, host)
	} else {
		addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if err != nil || len(addrs) == 0 {
		return fail(KindDNS, "имя не находится")
	}
	addr := addrs[0].Unmap()
	for _, a := range addrs {
		if a.Unmap().Is4() {
			addr = a.Unmap() // IPv4 first: not every network routes IPv6
			break
		}
	}
	if p.Resolve == nil && stubAddr(addr) {
		return fail(KindDNSStub, "имя указывает на "+addr.String())
	}

	// The connection, from a port of the slot.
	var conn net.Conn
	for try := 0; ; try++ {
		d := net.Dialer{LocalAddr: &net.TCPAddr{Port: p.port()}}
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		var se *os.SyscallError
		if err != nil && errors.As(err, &se) && se.Syscall == "bind" && try < 10 {
			continue // the port is taken (TIME_WAIT, a reserved range): the next one
		}
		break
	}
	if err != nil {
		return fail(KindIP, "соединение не устанавливается: "+shortErr(err))
	}
	cc := &countConn{Conn: conn}
	defer cc.Close()
	if dl, ok := ctx.Deadline(); ok {
		cc.SetDeadline(dl)
	}

	// The handshake, as Chrome.
	tc := utls.UClient(cc, &utls.Config{ServerName: host, RootCAs: p.Roots}, utls.HelloChrome_Auto)
	if err := tc.HandshakeContext(ctx); err != nil {
		var ce *utls.CertificateVerificationError
		if errors.As(err, &ce) || strings.Contains(err.Error(), "certificate") {
			return fail(KindCert, "чужой сертификат")
		}
		return fail(KindTLS, "рукопожатие: "+shortErr(err))
	}

	// The answer.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Encoding", "identity")
	var resp *http.Response
	if tc.ConnectionState().NegotiatedProtocol == "h2" {
		var h2 *http2.ClientConn
		if h2, err = (&http2.Transport{}).NewClientConn(tc); err == nil {
			defer h2.Close()
			resp, err = h2.RoundTrip(req)
		}
	} else {
		req.Close = true
		if err = req.Write(tc); err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(tc), req)
		}
	}
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fail(KindNoAnswer, fmt.Sprintf("ответ %d", resp.StatusCode))
		}
		if _, err = io.CopyN(io.Discard, resp.Body, maxBody); errors.Is(err, io.EOF) {
			err = nil
		}
	}
	if err != nil {
		return fail(KindFreeze, fmt.Sprintf("оборвалось после %d КБ: %s", (cc.n.Load()+512)>>10, shortErr(err)))
	}
	return nil
}

// stubAddr: an address no public site has. Providers answer blocked names
// with such addresses (0.0.0.0, 127.0.0.1, an address of their network).
func stubAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func shortErr(err error) string {
	var ne net.Error
	switch s := strings.ToLower(err.Error()); {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		return "нет ответа"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed"):
		return "соединение сброшено"
	case strings.Contains(s, "refused"):
		return "соединение отклонено"
	case strings.Contains(s, "eof"):
		return "соединение закрыто"
	case strings.Contains(s, "unreachable"):
		return "адрес недоступен"
	}
	return err.Error()
}
