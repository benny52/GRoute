package tgws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// encodeDomain is decodeDomain's inverse (a name.co.uk to tg-ws-proxy's
// form).
func encodeDomain(s string) string {
	p := strings.TrimSuffix(s, ".co.uk")
	n := 0
	for _, c := range p {
		if c >= 'a' && c <= 'z' {
			n++
		}
	}
	var b strings.Builder
	for _, c := range p {
		if c >= 'a' && c <= 'z' {
			c = 'a' + (c-'a'+rune(n))%26
		}
		b.WriteRune(c)
	}
	return b.String() + ".com"
}

func TestCloudflareList(t *testing.T) {
	for _, d := range []string{"abc.co.uk", "zz-top9.co.uk", "xyzxyzxyzxyzxyzxyzxyzxyzxyzxyz.co.uk"} {
		if got := decodeDomain(encodeDomain(d)); got != d {
			t.Fatalf("%s → %s → %s", d, encodeDomain(d), got)
		}
	}
	if decodeDomain("plain.example") != "plain.example" {
		t.Fatal("a name without .com is taken as it is")
	}
	def := DefaultCloudflare()
	if len(def) != len(cloudflareEncoded) {
		t.Fatalf("%d of %d", len(def), len(cloudflareEncoded))
	}
	for _, d := range def {
		if !strings.HasSuffix(d, ".co.uk") || !ValidHost(d) {
			t.Fatalf("%q", d)
		}
	}
	list := ParseCloudflare("# comment\n" + encodeDomain("one.co.uk") + "\n\n" + encodeDomain("one.co.uk") + "\nbad_name.com\n" + encodeDomain("two.co.uk") + "\n")
	if !slices.Equal(list, []string{"one.co.uk", "two.co.uk"}) {
		t.Fatalf("%q", list)
	}
	for _, c := range []struct {
		host string
		ok   bool
	}{{"w.user.workers.dev", true}, {"x.y", false}, {"localhost", false}, {"-a.dev", false}, {"a.123", false}, {"a b.dev", false}} {
		if ValidHost(c.host) != c.ok {
			t.Fatalf("%q", c.host)
		}
	}
}

func TestFetchCloudflare(t *testing.T) {
	body := encodeDomain("aa.co.uk") + "\n" + encodeDomain("bb.co.uk") + "\n" + encodeDomain("cc.co.uk") + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	// The URL is GitHub's: a transport sends it to the test server.
	client := &http.Client{Transport: rewrite{srv.URL, http.DefaultTransport}}
	list, err := FetchCloudflare(context.Background(), client)
	if err != nil || !slices.Equal(list, []string{"aa.co.uk", "bb.co.uk", "cc.co.uk"}) {
		t.Fatalf("%q %v", list, err)
	}
	body = encodeDomain("aa.co.uk") + "\n"
	if _, err := FetchCloudflare(context.Background(), client); err == nil {
		t.Fatal("a list of one taken")
	}
}

type rewrite struct {
	base string
	rt   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(r.base, "http://")
	req = req.Clone(req.Context())
	req.URL = &u
	return r.rt.RoundTrip(req)
}

// cfNames are the fake's certificate names for two Cloudflare domains and
// a Worker.
var cfNames = append(slices.Clone(kwsNames), "kws1.cf-a.test", "kws2.cf-a.test", "kws4.cf-a.test",
	"kws1.cf-b.test", "kws2.cf-b.test", "kws4.cf-b.test", "w.user.workers.dev")

// Telegram's WebSocket refused: connections go through Cloudflare, a dead
// domain is skipped for the next one, and Cloudflare goes before the VPN
// only when told so.
func TestBridgeCloudflare(t *testing.T) {
	f := newFakeTG(t, cfNames...)
	for _, h := range kwsNames {
		f.refuse[h] = 302
	}
	f.blockSNI["kws1.cf-a.test"] = true
	var vpn atomic.Int32
	var vpnUp atomic.Bool
	vpnUp.Store(true)
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: -1,
		Cloudflare: []string{"cf-a.test", "cf-b.test"}, CloudflareFirst: true,
		VPN: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			vpn.Add(1)
			if !vpnUp.Load() {
				return nil, errors.New("down")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.tcp.Addr().String())
		}})
	for _, idx := range []int16{1, 1, -2, 4} {
		tc := dialClient(t, p.Addr().String(), secret, ProtoIntermediate, idx)
		echo(t, tc, 64, 3000)
		tc.c.Close()
		s := f.seen()
		last := s[len(s)-1]
		dc := idx
		if dc < 0 {
			dc = -dc
		}
		if last.via != "ws" || last.dc != idx || !strings.HasPrefix(last.host, fmt.Sprintf("kws%d.cf-", dc)) {
			t.Fatalf("%+v", last)
		}
		if idx == 1 && last.host != "kws1.cf-b.test" {
			t.Fatalf("a blocked domain used: %+v", last)
		}
	}
	if n := f.unaligned.Load(); n != 0 {
		t.Fatalf("%d messages not one packet", n)
	}
	if st := b.Stats(); st.Routes[RouteCF] != 4 || vpn.Load() != 0 || st.Routes[RouteWS] != 0 {
		t.Fatalf("%+v vpn=%d", st, vpn.Load())
	}
	// Cloudflare after the VPN: the VPN takes it; the VPN down, Cloudflare.
	b.SetCloudflare([]string{"cf-b.test"}, false)
	tc := dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 1)
	echo(t, tc, 64)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteVPN] != 1 {
		t.Fatalf("%+v", st)
	}
	vpnUp.Store(false)
	tc = dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 1)
	echo(t, tc, 64)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteCF] != 5 || st.Routes[RouteTCP] != 0 {
		t.Fatalf("%+v", st)
	}
}

// A Worker of the user's: tried before the domains, told the data
// center's address.
func TestBridgeWorker(t *testing.T) {
	f := newFakeTG(t, cfNames...)
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: -1, Redirect: map[int]netip.Addr{},
		Cloudflare: []string{"cf-a.test"}, Workers: []string{"w.user.workers.dev"}})
	tc := dialClient(t, p.Addr().String(), secret, ProtoAbridged, 4)
	echo(t, tc, 64, 70000)
	tc.c.Close()
	s := f.seen()
	if len(s) != 1 || s[0].host != "w.user.workers.dev" || s[0].query != "dc=4&dst=149.154.167.91" || s[0].dc != 4 {
		t.Fatalf("%+v", s)
	}
	if st := b.Stats(); st.Routes[RouteWorker] != 1 {
		t.Fatalf("%+v", st)
	}
	// The Worker gone: the domain.
	f.mu.Lock()
	f.blockSNI["w.user.workers.dev"] = true
	f.mu.Unlock()
	tc = dialClient(t, p.Addr().String(), secret, ProtoAbridged, 4)
	echo(t, tc, 64)
	tc.c.Close()
	if s := f.seen(); s[len(s)-1].host != "kws4.cf-a.test" {
		t.Fatalf("%+v", s)
	}
}

// Telegram with no proxy set, to a data center without WebSocket:
// Cloudflare when it goes first, else passed on unchanged.
func TestTransparentCloudflare(t *testing.T) {
	f := newFakeTG(t, cfNames...)
	b := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots,
		Redirect:   map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1")},
		Cloudflare: []string{"cf-a.test"}, CloudflareFirst: true,
		VPN: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return f.dial(ctx, "tcp", dst.String())
		}})
	defer b.Close()
	dc1 := transparent(t, b, "149.154.175.50:443")
	tc := dialClient(t, dc1, nil, ProtoIntermediate, 1)
	echo(t, tc, 32, 5000)
	tc.c.Close()
	if s := f.seen(); len(s) != 1 || s[0].host != "kws1.cf-a.test" {
		t.Fatalf("%+v", s)
	}
	// web.telegram.org's TLS: never through Cloudflare.
	web := transparent(t, b, webAddr)
	c, _ := net.Dial("tcp", web)
	hello := append([]byte{0x16, 3, 1, 2, 0}, make([]byte, 200)...)
	c.Write(hello)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(hello))); err != nil {
		t.Fatal(err)
	}
	c.Close()
	b.SetCloudflare([]string{"cf-a.test"}, false)
	tc = dialClient(t, dc1, nil, ProtoIntermediate, 1)
	echo(t, tc, 32)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteCF] != 1 || st.Routes[RouteVPN] != 2 {
		t.Fatalf("%+v", st)
	}
}

// Media over WebSocket that never get an answer: after mediaStrikes the
// data center's media skip WebSocket; its other connections keep it.
func TestMediaOff(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	f.silent["kws2-1.web.telegram.org"] = true
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: -1})
	for range mediaStrikes {
		tc := dialClient(t, p.Addr().String(), secret, ProtoIntermediate, -2)
		tc.send(t, packet(ProtoIntermediate, make([]byte, 32)))
		time.Sleep(50 * time.Millisecond)
		tc.c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(b.Stats().MediaOff) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if off := b.Stats().MediaOff; !slices.Equal(off, []int{2}) {
		t.Fatalf("%v", off)
	}
	before := f.accepts.Load()
	tc := dialClient(t, p.Addr().String(), secret, ProtoIntermediate, -2)
	echo(t, tc, 32)
	tc.c.Close()
	tc = dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 2)
	echo(t, tc, 32)
	tc.c.Close()
	if f.accepts.Load() != before+1 || b.Stats().Routes[RouteTCP] != 1 {
		t.Fatalf("accepts %d→%d %+v", before, f.accepts.Load(), b.Stats())
	}
	// An answered media connection keeps WebSocket.
	b2 := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots,
		Redirect: map[int]netip.Addr{4: netip.MustParseAddr("127.0.0.1")}})
	defer b2.Close()
	h := Hello{DC: 4, Media: true}
	b2.mediaResult(h, 10, 0)
	b2.mediaResult(h, 10, 0)
	b2.mediaResult(h, 10, 5)
	b2.mediaResult(h, 10, 0)
	b2.mediaResult(h, 0, 0) // the client sent nothing: not counted
	if !b2.wsUsable(h) {
		t.Fatal("off after an answer between")
	}
}

// Self-checks see Cloudflare: a route that does not answer is skipped by
// connections until it answers again.
func TestCheckCloudflare(t *testing.T) {
	f := newFakeTG(t, cfNames...)
	f.refuse["kws2.web.telegram.org"] = 302
	b := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots,
		Redirect:   map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1")},
		Cloudflare: []string{"cf-a.test"}, CloudflareFirst: true})
	defer b.Close()
	h := b.Check(context.Background())
	if h.WS || !h.CF || h.CFRoute != RouteCF || b.cfDown.Load() {
		t.Fatalf("%+v", h)
	}
	f.mu.Lock()
	f.blockSNI["kws2.cf-a.test"] = true
	f.mu.Unlock()
	old := cfBackoff
	cfBackoff = 0
	defer func() { cfBackoff = old }()
	h = b.Check(context.Background())
	if h.CF || h.CFError == "" || !b.cfDown.Load() {
		t.Fatalf("%+v", h)
	}
	if b.cfUsable(Hello{DC: 1}) {
		t.Fatal("Cloudflare used while down")
	}
	f.mu.Lock()
	f.blockSNI = map[string]bool{}
	f.mu.Unlock()
	if h = b.Check(context.Background()); !h.CF || b.cfDown.Load() {
		t.Fatalf("%+v", h)
	}
	// No Cloudflare set up: not checked.
	b2 := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots, Redirect: map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1")}})
	defer b2.Close()
	if h := b2.Check(context.Background()); h.CF || h.CFError != "" {
		t.Fatalf("%+v", h)
	}
}
