package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	proxy := &socks5.Server{}
	if err := proxy.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	requested, releaseHTTP := make(chan struct{}), make(chan struct{})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("203.0.113.7\n")) }))
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
	if err != nil || !out.OK || out.ExternalIP != "203.0.113.7" || len(out.Steps) != 4 {
		t.Fatalf("%+v %v", out, err)
	}
	if len(runners) != 1 || runners[0].up {
		t.Fatal("temporary Hysteria must be stopped after the check")
	}
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
