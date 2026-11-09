package tgws

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"
)

// TestLiveTelegram asks real Telegram, through the bridge as a local proxy,
// for the first step of a key exchange (req_pq_multi, needs no account)
// and checks its answer (resPQ with the same nonce): the whole chain, the
// obfuscation both ways and the WebSocket framing, against the real
// servers. HYROUTE_TGWS_LIVE=1 runs it (CI does; the network must reach
// Telegram).
func TestLiveTelegram(t *testing.T) {
	if os.Getenv("HYROUTE_TGWS_LIVE") == "" {
		t.Skip("HYROUTE_TGWS_LIVE=1 runs it against Telegram")
	}
	for _, c := range []struct {
		name  string
		idx   int16
		route string // "" = any
		cfg   Config
		front bool // the fronted name first
	}{
		{"DC2 WebSocket", 2, RouteWS, Config{NoFronting: true, PoolSize: -1}, false},
		{"DC4 media WebSocket", -4, "", Config{NoFronting: true, PoolSize: -1}, false},
		{"DC2 fronted", 2, RouteFronted, Config{PoolSize: -1}, true},
		{"DC1 direct TCP", 1, RouteTCP, Config{PoolSize: -1}, false},
		// tg-ws-proxy's Cloudflare domains (the built-in list): a data
		// center without WebSocket, and media.
		{"DC1 Cloudflare", 1, RouteCF, Config{PoolSize: -1, Redirect: map[int]netip.Addr{}, Cloudflare: DefaultCloudflare(), CloudflareFirst: true}, false},
		{"DC4 media Cloudflare", -4, RouteCF, Config{PoolSize: -1, Redirect: map[int]netip.Addr{}, Cloudflare: DefaultCloudflare(), CloudflareFirst: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := New(c.cfg)
			defer b.Close()
			if c.front {
				b.fronted.Store(true)
			}
			p := &Proxy{Bridge: b, Secret: NewSecret()}
			if err := p.Listen("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			tc := dialClient(t, p.Addr().String(), p.Secret, ProtoIntermediate, c.idx)
			defer tc.c.Close()
			var nonce [16]byte
			rand.Read(nonce[:])
			msg := make([]byte, 0, 40)
			msg = binary.LittleEndian.AppendUint64(msg, 0) // auth_key_id: none yet
			msg = binary.LittleEndian.AppendUint64(msg, uint64(time.Now().Unix())<<32|4)
			msg = binary.LittleEndian.AppendUint32(msg, 20)
			msg = binary.LittleEndian.AppendUint32(msg, 0xbe7e8ef1) // req_pq_multi
			msg = append(msg, nonce[:]...)
			tc.send(t, packet(ProtoIntermediate, msg))
			n := int(binary.LittleEndian.Uint32(tc.recv(t, 4)))
			if n < 40 || n > 1024 {
				t.Fatalf("an answer of %d bytes (%+v)", n, liveStats(b))
			}
			ans := tc.recv(t, n)
			if c := binary.LittleEndian.Uint32(ans[20:]); c != 0x05162463 || !bytes.Equal(ans[24:40], nonce[:]) {
				t.Fatalf("not resPQ: %x", ans[:min(len(ans), 48)])
			}
			st := liveStats(b)
			if c.route != "" && st.Routes[c.route] != 1 {
				t.Fatalf("%+v", st)
			}
			t.Logf("%s: resPQ via %s", c.name, st.LastRoute)
		})
	}
}

// TestLiveFronting says what Telegram's WebSocket server answers to a
// TLS name other than its own: the certificate it presents (names,
// issuer) and whether it verifies for kws2.web.telegram.org. Information
// only: whether fronting works depends on the network.
func TestLiveFronting(t *testing.T) {
	if os.Getenv("HYROUTE_TGWS_LIVE") == "" {
		t.Skip("HYROUTE_TGWS_LIVE=1 runs it against Telegram")
	}
	for _, sni := range []string{FrontingSNI, "kws2.web.telegram.org", ""} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", "149.154.167.220:443",
			&tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			t.Logf("SNI %q: %v", sni, err)
			continue
		}
		cs := c.ConnectionState()
		leaf := cs.PeerCertificates[0]
		opts := x509.VerifyOptions{DNSName: "kws2.web.telegram.org", Intermediates: x509.NewCertPool()}
		for _, ic := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		_, verr := leaf.Verify(opts)
		t.Logf("SNI %q: names %v, issuer %q, verifies for kws2: %v", sni, leaf.DNSNames, leaf.Issuer.CommonName, verr)
		c.Close()
	}
	w, err := dialWS(context.Background(), (&net.Dialer{}).DialContext, wsTarget{Addr: "149.154.167.220:443", Host: "kws2.web.telegram.org", SNI: FrontingSNI, Path: "/apiws"})
	t.Logf("fronted WebSocket: %v", err)
	if w != nil {
		w.Close()
	}
}

// TestLiveCheck runs the self-check against real Telegram: WebSocket
// answers, nothing is skipped.
func TestLiveCheck(t *testing.T) {
	if os.Getenv("HYROUTE_TGWS_LIVE") == "" {
		t.Skip("HYROUTE_TGWS_LIVE=1 runs it against Telegram")
	}
	b := New(Config{PoolSize: -1})
	defer b.Close()
	h := b.Check(context.Background())
	if !h.WS || b.wsDown.Load() {
		t.Fatalf("%+v", h)
	}
	t.Logf("self-check: WebSocket via %s in %d ms", h.WSRoute, h.WSMillis)
}

// liveStats are the bridge's counters without the latest error, which may
// name a Cloudflare domain (the logs of CI are public; the list is kept
// encoded so that its names are not read in plain text).
func liveStats(b *Bridge) Stats {
	st := b.Stats()
	if st.LastError != "" {
		st.LastError = "(скрыто)"
	}
	return st
}

// TestLiveCloudflare takes tg-ws-proxy's current list and checks the
// self-check through Cloudflare alone; the names are not logged.
func TestLiveCloudflare(t *testing.T) {
	if os.Getenv("HYROUTE_TGWS_LIVE") == "" {
		t.Skip("HYROUTE_TGWS_LIVE=1 runs it against Telegram")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := FetchCloudflare(ctx, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	same := 0
	for _, d := range DefaultCloudflare() {
		if slices.Contains(list, d) {
			same++
		}
	}
	t.Logf("the list: %d domains, %d of them built in", len(list), same)
	b := New(Config{PoolSize: -1, Redirect: map[int]netip.Addr{}, Cloudflare: list, CloudflareFirst: true})
	defer b.Close()
	h := b.Check(ctx)
	if !h.CF || b.cfDown.Load() {
		t.Fatalf("Cloudflare did not answer (%d chars of error)", len(h.CFError))
	}
	t.Logf("self-check: Cloudflare via %s in %d ms", h.CFRoute, h.CFMillis)
}
