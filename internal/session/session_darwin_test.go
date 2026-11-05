//go:build darwin

package session

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

// TestTUNSession routes this Mac through a real utun device: curl's
// connections go through the relay into a tunnel (the in-process SOCKS5
// stub) or direct, dig's UDP through the tunnel or the forwarder. It
// changes the routing table, so it runs as root on a CI machine only
// (HYROUTE_TUN_TEST=1).
func TestTUNSession(t *testing.T) {
	if os.Getenv("HYROUTE_TUN_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs root and HYROUTE_TUN_TEST=1: it routes the whole machine")
	}
	compile := func(a rules.Action) *rules.Set {
		set, err := rules.Compile(rules.Config{DefaultAction: a, DefaultProfile: "p1"})
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	profiles := []hysteria.Profile{{ID: "p1", Name: "stub"}}
	s, err := Start(Config{Stub: true, Settings: &settings.Settings{}, Rules: compile(rules.Tunnel), Profiles: profiles, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			s.Stop()
		}
	}()
	waitTunnel(t, s)

	curl := func() {
		t.Helper()
		out, err := exec.Command("curl", "-sS", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com/").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "200" {
			t.Fatalf("curl: %v %s", err, out)
		}
	}
	dig := func() {
		t.Helper()
		out, err := exec.Command("dig", "+short", "+time=5", "+tries=2", "@1.1.1.1", "example.com", "A").CombinedOutput()
		if err != nil || net.ParseIP(strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])) == nil {
			t.Fatalf("dig: %v %s", err, out)
		}
	}

	curl()
	st := s.Stats()
	if st.RelayTunnel < 1 || st.Reflected < 1 {
		t.Fatalf("curl not tunneled: %+v", st)
	}
	if !seen(s, "curl", "tunnel") {
		t.Fatalf("no tunneled record of curl: %+v", s.Flows().Closed())
	}
	dig()
	if st := s.Stats(); st.UDPTunneled < 1 {
		t.Fatalf("dig not tunneled: %+v", st)
	}

	s.SetRules(compile(rules.Direct), profiles)
	before := s.Stats().RelayDirect
	curl()
	if st := s.Stats(); st.RelayDirect <= before {
		t.Fatalf("curl not relayed direct: %+v", st)
	}
	if !seen(s, "curl", "direct") {
		t.Fatal("no direct record of curl")
	}
	dig()

	s.Stop()
	stopped = true
	// The routes went with the device: the Mac goes direct again.
	curl()
	if ifs, _ := net.Interfaces(); hasUTUNAddr(ifs) {
		t.Fatal("the TUN device outlived Stop")
	}
}

func waitTunnel(t *testing.T, s *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		if e := s.Endpoint("p1"); e != nil && e.Available() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("stub tunnel not up")
}

func seen(s *Session, process, route string) bool {
	for _, v := range append(s.Flows().Active(time.Now()), s.Flows().Closed()...) {
		if v.Process == process && v.Route == route {
			return true
		}
	}
	return false
}

func hasUTUNAddr(ifs []net.Interface) bool {
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if strings.HasPrefix(a.String(), "198.18.0.1/") {
				return true
			}
		}
	}
	return false
}
