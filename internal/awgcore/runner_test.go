package awgcore

import (
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Use a child running this test binary to exercise actual Windows pipes,
// process termination and version negotiation without real credentials.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--serve" {
		os.Exit(testCore())
	}
	os.Exit(m.Run())
}

func testCore() int {
	enc := json.NewEncoder(os.Stdout)
	version := Protocol
	if os.Getenv("GROUTE_TEST_CORE") == "incompatible" {
		version++
	}
	if enc.Encode(Event{Type: "hello", Version: version}) != nil {
		return 1
	}
	var request Request
	if Read(Reader(os.Stdin), &request) != nil || !strings.Contains(request.Config, "Endpoint = 127.0.0.1:2345") {
		return 1
	}
	state := hysteria.Status{State: hysteria.Connected, UDPEnabled: true, SOCKS: "127.0.0.1:9999"}
	if enc.Encode(Event{Type: "ready", Status: state, Username: "example", Password: "test-only"}) != nil {
		return 1
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	return 0
}

func TestCoreLifecycle(t *testing.T) {
	profile := hysteria.Profile{Host: "127.0.0.1", Ports: "2345"}
	var excluded []netip.Addr
	r := NewRunner(os.Executable, profile, tunnels.Hooks{SetServerIPs: func(ips []netip.Addr) error {
		excluded = ips
		return nil
	}})
	t.Cleanup(r.Stop)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if !r.Available() || !r.UDPAvailable() || r.SOCKS().Password == "" || len(excluded) != 1 {
		t.Fatal("ready core should provide a proxy and an endpoint exclusion")
	}
	proc := r.run
	if err := proc.child.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not detect child exit")
	}
	if r.Status().State != hysteria.Failed || r.Available() || r.UDPAvailable() || r.SOCKS().Password != "" || len(excluded) != 0 {
		t.Fatal("crashed core retained live state")
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.Stop()
	if r.Status().State != hysteria.Stopped || r.SOCKS().Server != "" || len(excluded) != 0 {
		t.Fatal("stopped core retained live state")
	}
}

func TestCoreVersionMismatch(t *testing.T) {
	t.Setenv("GROUTE_TEST_CORE", "incompatible")
	r := NewRunner(os.Executable, hysteria.Profile{Host: "127.0.0.1", Ports: "2345"}, tunnels.Hooks{})
	t.Cleanup(r.Stop)
	if err := r.Start(); err == nil || !strings.Contains(err.Error(), "протокол") {
		t.Fatalf("expected protocol incompatibility, got %v", err)
	}
	if r.Status().State != hysteria.Failed || r.SOCKS().Server != "" {
		t.Fatal("incompatible core is usable")
	}
}
