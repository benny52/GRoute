//go:build integration && (windows || darwin)

package session

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	legacyConn "github.com/amnezia-vpn/amneziawg-go/conn"
	legacyDevice "github.com/amnezia-vpn/amneziawg-go/device"
	legacyStack "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Both isolated netstacks own this same destination. The reply prefix therefore
// proves which encrypted peer carried the request even after a routing change.
var echoAddr = netip.MustParseAddrPort("10.77.0.1:4567")

type testAWGDevice interface {
	IpcGet() (string, error)
	IpcSet(string) error
	Up() error
	Close()
}

type testEchoNetwork interface {
	ListenTCPAddrPort(netip.AddrPort) (*gonet.TCPListener, error)
	ListenUDPAddrPort(netip.AddrPort) (*gonet.UDPConn, error)
}

// Use the pre-3.x implementation for the 2.0 peer. This catches a pair
// of 3.1 devices accidentally agreeing on a 3.1-only wire format.
func newPeerStack(t *testing.T, version string) (testAWGDevice, testEchoNetwork) {
	t.Helper()
	ips := []netip.Addr{echoAddr.Addr()}
	if version == "2.0" {
		tun, ns, err := legacyStack.CreateNetTUN(ips, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		return legacyDevice.NewDevice(tun, legacyConn.NewStdNetBind(), legacyDevice.NewLogger(legacyDevice.LogLevelSilent, "")), ns
	}
	tun, ns, err := netstack.CreateNetTUN(ips, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	return device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, "")), ns
}

func newTestPeer(t *testing.T, version string) (hysteria.Profile, func()) {
	t.Helper()
	key := func() *ecdh.PrivateKey {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	client, server := key(), key()
	d, ns := newPeerStack(t, version)
	closeDevice := sync.OnceFunc(d.Close)
	t.Cleanup(closeDevice)
	common := "s1=16\ns2=23\ns3=18\ns4=19\nh1=110-119\nh2=210-219\nh3=310-319\nh4=410-419\n"
	conf := "S1 = 16\nS2 = 23\nS3 = 18\nS4 = 19\nH1 = 110-119\nH2 = 210-219\nH3 = 310-319\nH4 = 410-419\n"
	if version == "3.1" {
		headerKey := key().Bytes()
		common += "header_protection_key=" + hex.EncodeToString(headerKey) + "\nrandom_trailers=true\n"
		conf += "HeaderProtectionKey = " + base64.StdEncoding.EncodeToString(headerKey) + "\nRandomTrailers = true\n"
	}
	ipc := fmt.Sprintf("private_key=%x\nlisten_port=0\n%spublic_key=%x\nallowed_ip=10.77.0.2/32\n", server.Bytes(), common, client.PublicKey().Bytes())
	if err := d.IpcSet(ipc); err != nil {
		t.Fatal("peer rejected synthetic parameters")
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	state, err := d.IpcGet()
	if err != nil {
		t.Fatal("cannot read peer endpoint")
	}
	port := ""
	for line := range strings.SplitSeq(state, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port = v
			break
		}
	}
	if port == "" || port == "0" {
		t.Fatal("peer has no transport port")
	}
	cfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/32\n%s[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%s\nAllowedIPs = 10.77.0.1/32\n", base64.StdEncoding.EncodeToString(client.Bytes()), conf, base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), port)
	profile, err := hysteria.ParseAWGConfig(cfg)
	if err != nil {
		t.Fatal("client rejected synthetic "+version+" parameters:", err)
	}
	// Exercise the same two link wrappers supplied by the subscription
	// parser, then route using the imported profile.
	scheme := "vpn://"
	if version == "3.1" {
		scheme = "amneziawg://"
	}
	link := scheme + base64.RawURLEncoding.EncodeToString([]byte(cfg))
	imported, _, err := hysteria.ParseURI(link)
	if err != nil || !hysteria.SameConnection(imported, profile) {
		t.Fatal("link and .conf disagree")
	}
	profile = imported
	profile.ID, profile.Name = version, "Test "+version
	tcp, err := ns.ListenTCPAddrPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := ns.ListenUDPAddrPort(echoAddr)
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	closePeer := sync.OnceFunc(func() { tcp.Close(); udp.Close(); closeDevice() })
	t.Cleanup(closePeer)
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				b := make([]byte, 4)
				if _, e := io.ReadFull(c, b); e == nil {
					fmt.Fprintf(c, "%s/%s", version, b)
				}
			}()
		}
	}()
	go func() {
		buf := make([]byte, 256)
		for {
			n, src, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			udp.WriteTo(append([]byte(version+"/"), buf[:n]...), src)
		}
	}()
	return profile, closePeer
}

func TestAmneziaWGPeerFailover(t *testing.T) {
	for _, order := range [][]string{{"2.0", "3.1"}, {"3.1", "2.0"}} {
		t.Run(strings.Join(order, "-to-"), func(t *testing.T) {
			t.Parallel()
			primary, cut := newTestPeer(t, order[0])
			spare, _ := newTestPeer(t, order[1])
			mgr := &tunnels.Manager{New: RunnerFactory(Config{Log: slog.Default()})}
			t.Cleanup(mgr.StopAll)
			mgr.Sync([]hysteria.Profile{primary, spare})
			waitFor := func(label string, deadline time.Duration, ok func() bool) {
				t.Helper()
				until := time.Now().Add(deadline)
				for !ok() {
					if time.Now().After(until) {
						t.Fatal(label)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			waitFor("initial handshake timed out", 10*time.Second, func() bool { return mgr.Get(primary.ID).Available() && mgr.Get(spare.ID).Available() })
			replies := make(chan string, 8)
			core := engine.NewCore(engine.Options{NoDefaultExclusions: true}, func(id string) engine.Tunnel {
				if ep := mgr.Get(id); ep != nil {
					return ep
				}
				return nil
			}, procinfo.NewCache(), func(raw []byte, addr *divert.Address) {
				p, err := packet.Parse(raw)
				if err != nil {
					return
				}
				v := string(p.Payload())
				if addr.Outbound() {
					v = "DIRECT/" + v
				}
				replies <- v
			})
			t.Cleanup(core.Close)
			cfg, err := rules.Compile(rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{
				{Name: "AWG echo", Ports: rules.PortList{"4567"}, Action: rules.Tunnel, Profile: primary.ID, Fallback: []string{spare.ID}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			core.Rules.Swap(cfg)
			src := netip.MustParseAddrPort("192.0.2.25:50420")
			core.Conns.Connect(attrib.Key5{Proto: packet.ProtoUDP, Local: src, Remote: echoAddr}, 424242, 1, time.Now())
			exchange := func(want string, fallback bool) {
				t.Helper()
				r := core.RelayDecide(&nat.Entry{Flow: nat.FlowKey{Dst: echoAddr}}, "echo.test", rules.SrcSNI)
				if r.Profile != want || r.Failover != fallback || r.Action != rules.Tunnel {
					t.Fatalf("TCP decision = %+v", r)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, err := mgr.Get(r.Profile).Dial(ctx, socks5.AddrFromAddrPort(echoAddr))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err := io.WriteString(c, "ping"); err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(io.LimitReader(c, 64))
				if err != nil || string(b) != want+"/ping" {
					t.Fatalf("TCP response %q, err %v", b, err)
				}
				var addr divert.Address
				addr.SetOutbound(true)
				// UDP delivery is best effort, including the first datagram of
				// a new loopback association. A phase-specific payload prevents
				// delayed replies from satisfying the check after cutover.
				payload := "ping-" + want
				for attempt := 0; attempt < 20; attempt++ {
					core.HandlePacket(packet.BuildUDP(src, echoAddr, []byte(payload)), &addr)
					select {
					case reply := <-replies:
						if reply != want+"/"+payload {
							t.Fatalf("UDP response %q, expected peer %s", reply, want)
						}
						t.Logf("TCP and UDP returned peer %s (fallback=%v)", want, fallback)
						return
					case <-time.After(250 * time.Millisecond):
					}
				}
				t.Fatalf("UDP timeout, sent %d, dropped %d", core.UDPTunneled.Load(), core.UDPDropped.Load())
			}
			exchange(primary.ID, false)
			cut()
			waitFor("silent peer still available", 45*time.Second, func() bool { return !mgr.Get(primary.ID).Available() })
			exchange(spare.ID, true)
		})
	}
}
