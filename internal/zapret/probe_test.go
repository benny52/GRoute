package zapret

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// local: every name resolves to the test server.
func local(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func tlsServer(t *testing.T, h2 bool, h http.HandlerFunc) (url string, roots *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://example.com:" + port + "/", roots
}

func TestProberOK(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		var mu sync.Mutex
		var ports []int
		var protos []string
		url, roots := tlsServer(t, h2, func(w http.ResponseWriter, r *http.Request) {
			_, p, _ := net.SplitHostPort(r.RemoteAddr)
			n, _ := strconv.Atoi(p)
			mu.Lock()
			ports, protos = append(ports, n), append(protos, r.Proto)
			mu.Unlock()
			w.Write(make([]byte, 200<<10)) // more than the check reads
		})
		p := &Prober{Slot: 3, Resolve: local, Roots: roots}
		r := p.Check(context.Background(), []string{url, url})
		if !r.OK || len(r.Failed) != 0 || r.Elapsed <= 0 {
			t.Fatalf("h2 %v: %+v", h2, r)
		}
		// Every address, every pass, from the ports of its slot.
		lo, hi := ProbeSlot(3)
		mu.Lock()
		if len(ports) != 2*Passes {
			t.Fatalf("%d requests", len(ports))
		}
		for i, n := range ports {
			if n < lo || n > hi || h2 != (protos[i] == "HTTP/2.0") {
				t.Fatalf("port %d (%d-%d), %s", n, lo, hi, protos[i])
			}
		}
		mu.Unlock()
	}
}

func TestProberKinds(t *testing.T) {
	old := CheckTimeout
	CheckTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { CheckTimeout = old })
	ctx := context.Background()

	// The connection freezes after 20 KB (TSPU).
	frozen, roots := tlsServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(100<<10))
		w.Write(make([]byte, 20<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	p := &Prober{Resolve: local, Roots: roots}
	r := p.Check(ctx, []string{frozen})
	if d := r.Diagnosis(); r.OK || d.Kind != KindFreeze || !r.Bypassable() || !strings.Contains(d.Text, "КБ") {
		t.Fatalf("freeze: %+v", r)
	}

	// The handshake is reset (DPI on the name).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 512))
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetLinger(0) // RST
			}
			c.Close()
		}
	}()
	r = p.Check(ctx, []string{"https://example.com:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/"})
	if d := r.Diagnosis(); d.Kind != KindTLS || !r.Bypassable() {
		t.Fatalf("reset: %+v", r)
	}

	// Nothing takes connections at the address.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	port := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	r = p.Check(ctx, []string{"https://example.com:" + strconv.Itoa(port) + "/"})
	if d := r.Diagnosis(); d.Kind != KindIP || r.Bypassable() {
		t.Fatalf("ip: %+v", r)
	}

	// Someone else's certificate.
	other, _ := tlsServer(t, false, func(w http.ResponseWriter, r *http.Request) {})
	r = (&Prober{Resolve: local, Roots: x509.NewCertPool()}).Check(ctx, []string{other})
	if d := r.Diagnosis(); d.Kind != KindCert || r.Bypassable() {
		t.Fatalf("cert: %+v", r)
	}

	// No name; the worst failure explains the target.
	r = (&Prober{Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }}).Check(ctx, []string{other})
	if d := r.Diagnosis(); d.Kind != KindDNS || r.Bypassable() || d.Kind.Explain() == "" {
		t.Fatalf("dns: %+v", r)
	}
	mixed := Result{Failed: []Failure{{Kind: KindFreeze}, {Kind: KindIP}, {Kind: KindTLS}}}
	if mixed.Diagnosis().Kind != KindIP || mixed.Bypassable() {
		t.Fatalf("%+v", mixed.Diagnosis())
	}
	for a, stub := range map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "10.1.2.3": true, "100.64.1.1": true, "::ffff:192.168.0.1": true, "142.250.1.1": false} {
		if stubAddr(netip.MustParseAddr(a)) != stub {
			t.Errorf("stub %s", a)
		}
	}
}

func TestProbeFilters(t *testing.T) {
	lo, hi := ProbeSlot(1)
	if lo != ProbePortBase+ProbeSlotSize || hi != lo+ProbeSlotSize-1 {
		t.Fatalf("%d-%d", lo, hi)
	}
	_, top := ProbeSlot(ProbeSlots - 1)
	if top >= 49152 || len(Methods)+1 > ProbeSlots {
		t.Fatalf("slots end at %d for %d methods", top, len(Methods))
	}
	if !strings.HasPrefix(ProbeExclude(), "not (") || !strings.Contains(ProbeOnly(2), "tcp.SrcPort >= 30300") {
		t.Fatalf("%s\n%s", ProbeExclude(), ProbeOnly(2))
	}
}
