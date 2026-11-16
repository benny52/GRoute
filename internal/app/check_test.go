package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

type stubRunner struct {
	c  socks5.Client
	mu sync.Mutex
	up bool
	// socks-udp: noUDP is a server that does not allow UDP.
	noUDP bool
}

func (r *stubRunner) Start() error { r.mu.Lock(); r.up = true; r.mu.Unlock(); return nil }
func (r *stubRunner) Stop()        { r.mu.Lock(); r.up = false; r.mu.Unlock() }
func (r *stubRunner) Status() hysteria.Status {
	return hysteria.Status{State: hysteria.Connected, UDPEnabled: !r.noUDP}
}
func (r *stubRunner) Available() bool    { return true }
func (r *stubRunner) UDPAvailable() bool { return !r.noUDP }
func (r *stubRunner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return r.c.Connect(ctx, dst)
}
func (r *stubRunner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	return r.c.UDPAssociate(ctx)
}
func (r *stubRunner) SOCKS() socks5.Client { return r.c }

type batchTestRunner struct {
	stubRunner
	id      string
	started chan<- string
	probes  chan<- string
	finish  <-chan struct{}
}

func (r *batchTestRunner) Start() error {
	r.started <- r.id
	return r.stubRunner.Start()
}

func (r *batchTestRunner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	r.probes <- r.id
	select {
	case <-r.finish:
		return nil, errors.New("synthetic TCP failure")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestBatchParallelPreparationAndSerialProbes(t *testing.T) {
	for _, tc := range []struct {
		name string
		room int // -1: no routing session
		want int
	}{{"standalone", -1, 6}, {"limited session", 4, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newCtl(t)
			const count = 9
			var links []string
			for i := range count {
				links = append(links, fmt.Sprintf("hy2://test@server%d.invalid:443", i))
			}
			profiles, err := c.ImportURIs(strings.Join(links, "\n"))
			if err != nil || len(profiles.Added) != count {
				t.Fatal("test profiles", err)
			}
			started, probes := make(chan string, count), make(chan string, count)
			finish := make(chan struct{}, 1)
			c.Runners = func(p hysteria.Profile, _ tunnels.Hooks) tunnels.Runner {
				return &batchTestRunner{id: p.ID, started: started, probes: probes, finish: finish}
			}
			if tc.room >= 0 {
				c.sess = &liveSession{mgr: &tunnels.Manager{New: c.Runners}, room: tc.room}
			}
			token := c.BeginCheckBatch()
			results := make(chan error, count)
			var workers sync.WaitGroup
			defer func() { c.EndCheckBatch(token); workers.Wait() }()
			for _, p := range profiles.Added {
				workers.Go(func() {
					_, err := c.CheckBatchProfile(token, p.ID)
					results <- err
				})
			}
			for range tc.want {
				select {
				case <-started:
				case <-time.After(2 * time.Second):
					t.Fatal("too few parallel preparations")
				}
			}
			select {
			case <-probes:
			case <-time.After(2 * time.Second):
				t.Fatal("missing first probe")
			}
			select {
			case id := <-started:
				t.Fatalf("started extra runner %s", id)
			case id := <-probes:
				t.Fatalf("overlapping TCP measurement %s", id)
			case <-time.After(100 * time.Millisecond):
			}
			finish <- struct{}{}
			select {
			case err := <-results:
				if err != nil {
					t.Fatalf("first result: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("first check did not finish")
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("next server did not use the freed slot")
			}
			c.EndCheckBatch(token)
			for range count - 1 {
				select {
				case err := <-results:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("cancel did not reach every wait")
				}
			}
		})
	}
}

func TestBatchFullSessionStillChecksRoutingServer(t *testing.T) {
	c, _ := newCtl(t)
	routing, idle, _ := servers(t, c)
	m := &tunnels.Manager{New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		return &ctlRunner{dialErr: errors.New("synthetic TCP failure")}
	}}
	p, _ := c.Profile(routing)
	m.Sync([]hysteria.Profile{p})
	defer m.StopAll()
	c.sess = &liveSession{mgr: m, room: 0}
	token := c.BeginCheckBatch()
	defer c.EndCheckBatch(token)
	if _, err := c.CheckBatchProfile(token, idle); err == nil || !strings.Contains(err.Error(), "слишком много") {
		t.Fatalf("missing exclusion limit: %v", err)
	}
	result, err := c.CheckBatchProfile(token, routing)
	if err != nil || len(result.Steps) != 2 || !result.Steps[0].OK || !m.Get(routing).Available() {
		t.Fatalf("routing server was not checked in place: %+v, %v", result, err)
	}
}

type waitingCheckRunner struct {
	stubRunner
	started chan struct{}
}

func (r *waitingCheckRunner) Start() error {
	close(r.started)
	return r.stubRunner.Start()
}

func (r *waitingCheckRunner) Status() hysteria.Status {
	return hysteria.Status{State: hysteria.Connecting}
}

func TestCancelBatchReleasesPendingCheck(t *testing.T) {
	c, _ := newCtl(t)
	runner := &waitingCheckRunner{started: make(chan struct{})}
	c.Runners = func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return runner }
	added, _ := c.ImportURIs(link)
	id := added.Added[0].ID
	old, token := c.BeginCheckBatch(), c.BeginCheckBatch()
	defer c.EndCheckBatch(token)
	c.EndCheckBatch(old) // a late cancellation belongs to its original batch

	done := make(chan error, 1)
	go func() {
		_, err := c.CheckBatchProfile(token, id)
		done <- err
	}()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not start")
	}
	c.EndCheckBatch(token)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the pending connection")
	}
	if runner.up {
		t.Fatal("temporary runner still active")
	}
	if _, err := c.CheckBatchProfile(token, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled token accepted another check: %v", err)
	}
}

func TestCancelBatchHTTPKeepsSharedRunner(t *testing.T) {
	t.Run("determining external IP", func(t *testing.T) { cancelDuringProfileHTTP(t, true) })
	t.Run("measuring response", func(t *testing.T) { cancelDuringProfileHTTP(t, false) })
}

func cancelDuringProfileHTTP(t *testing.T, cancelOnFirstRequest bool) {
	proxy := &socks5.Server{}
	if err := proxy.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	requested, releaseHTTP := make(chan struct{}), make(chan struct{})
	var firstRequest sync.Once
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reply := false
		firstRequest.Do(func() { reply = !cancelOnFirstRequest })
		if reply {
			w.Write([]byte("203.0.113.7\n"))
			return
		}
		close(requested)
		select {
		case <-req.Context().Done():
		case <-releaseHTTP:
		}
	}))
	defer web.Close()
	defer close(releaseHTTP)
	oldIP, oldLatency := ipServices, latencyTarget
	defer func() { ipServices, latencyTarget = oldIP, oldLatency }()
	ipServices = []string{web.URL}
	latencyTarget = socks5.AddrFromAddrPort(web.Listener.Addr().(*net.TCPAddr).AddrPort())

	c, _ := newCtl(t)
	runner := &stubRunner{c: socks5.Client{Server: proxy.Addr()}, noUDP: true}
	c.Runners = func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return runner }
	added, _ := c.ImportURIs(link)
	id := added.Added[0].ID
	profile, err := c.Profile(id)
	if err != nil {
		t.Fatal(err)
	}
	_, release := c.acquire(profile) // a separate check already owns this endpoint
	defer release()
	token := c.BeginCheckBatch()
	defer c.EndCheckBatch(token)
	done := make(chan error, 1)
	go func() {
		_, err := c.CheckBatchProfile(token, id)
		done <- err
	}()
	select {
	case <-requested:
	case <-time.After(3 * time.Second):
		t.Fatal("no HTTP probe received")
	}
	c.EndCheckBatch(token)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request still running")
	}
	if !runner.up {
		t.Fatal("cancel stopped a runner shared with another check")
	}
}

func TestCheckProfileStandalone(t *testing.T) {
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	var calls []string
	var mu sync.Mutex
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls = append(calls, req.RemoteAddr)
		mu.Unlock()
		w.Write([]byte("203.0.113.7\n"))
	}))
	defer web.Close()
	dns, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer dns.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := dns.ReadFromUDP(b)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			m.Unpack(b[:n])
			m.Response = true
			out, _ := m.Pack()
			dns.WriteToUDP(out, a)
		}
	}()
	oldIP, oldLat, oldDNS := ipServices, latencyTarget, dnsProbe
	defer func() { ipServices, latencyTarget, dnsProbe = oldIP, oldLat, oldDNS }()
	ipServices = []string{web.URL}
	wa := web.Listener.Addr().(*net.TCPAddr).AddrPort()
	latencyTarget = socks5.AddrFromAddrPort(wa)
	dnsProbe = socks5.AddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dns.LocalAddr().(*net.UDPAddr).AddrPort().Port()))

	c, _ := newCtl(t)
	var runners []*stubRunner
	c.Runners = func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		r := &stubRunner{c: socks5.Client{Server: stub.Addr()}}
		runners = append(runners, r)
		return r
	}
	res, _ := c.ImportURIs(link)
	out, err := c.CheckProfile(res.Added[0].ID)
	if err != nil || !out.OK || out.ExternalIP != "203.0.113.7" || out.ResponseMs == nil || len(out.Steps) != 5 {
		t.Fatalf("%+v %v", out, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0] != calls[1] {
		t.Fatalf("expected a second HTTP request on the established connection, got %v", calls)
	}
	if len(runners) != 1 || runners[0].up {
		t.Fatal("temporary Hysteria must be stopped after the check")
	}
}

func TestResponseTimeAfterTLS(t *testing.T) {
	const handshakeDelay = 150 * time.Millisecond
	const serviceDelay = 25 * time.Millisecond
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(serviceDelay)
		w.WriteHeader(http.StatusOK)
	}))
	web.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		time.Sleep(handshakeDelay)
		return nil, nil
	}}
	web.StartTLS()
	defer web.Close()
	target, err := url.Parse(web.URL)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ms, err := responseTime(context.Background(), web.Client().Transport, target)
	if err != nil {
		t.Fatal(err)
	}
	if ms < serviceDelay.Milliseconds() || time.Since(start).Milliseconds()-ms < handshakeDelay.Milliseconds() {
		t.Fatalf("measured %d ms out of %v including TLS setup", ms, time.Since(start))
	}
}

func TestCheckWithoutResponseSample(t *testing.T) {
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	var first sync.Once
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reply := false
		first.Do(func() { reply = true })
		if reply {
			w.Write([]byte("203.0.113.7\n"))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer web.Close()
	oldIP, oldTCP := ipServices, latencyTarget
	defer func() { ipServices, latencyTarget = oldIP, oldTCP }()
	ipServices = []string{web.URL}
	latencyTarget = socks5.AddrFromAddrPort(web.Listener.Addr().(*net.TCPAddr).AddrPort())
	c, _ := newCtl(t)
	c.Runners = func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		return &stubRunner{c: socks5.Client{Server: stub.Addr()}, noUDP: true}
	}
	added, _ := c.ImportURIs(link)
	result, err := c.CheckProfile(added.Added[0].ID)
	if err != nil || !result.OK || result.ResponseMs != nil || result.ExternalIP != "203.0.113.7" {
		t.Fatalf("unavailable sample changed verdict: %+v %v", result, err)
	}
	for _, step := range result.Steps {
		if step.Skip && strings.Contains(step.Detail, "429") {
			return
		}
	}
	t.Fatal("missing reason for unavailable response time")
}

func TestDiagnosticsRedacts(t *testing.T) {
	c, _ := newCtl(t)
	c.Version = "test"
	c.ImportURIs("hysteria2://user:supersecret@203.0.113.50:443/?obfs=salamander&obfs-password=obfspass123#DE")
	c.Redactor.Set("supersecret", "obfspass123")
	c.Log.Warn("hysteria failed", "server", "203.0.113.50:443", "auth", "supersecret")
	d := c.Diagnostics([]string{"Драйвер: ok"}, false)
	if strings.Contains(d, "supersecret") || strings.Contains(d, "obfspass123") || !strings.Contains(d, "203.0.113.50") || !strings.Contains(d, "Драйвер: ok") {
		t.Fatal(d)
	}
	if p := c.Diagnostics(nil, true); strings.Contains(p, "203.0.113.50") || !strings.Contains(p, "203.xxx.xxx.50") {
		t.Fatal(p)
	}
}
