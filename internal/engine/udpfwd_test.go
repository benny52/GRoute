package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/packet"
)

func TestUDPForwarder(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			echo.WriteToUDPAddrPort(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	got := make(chan []byte, 4)
	f := &udpForwarder{
		listen: func(v6 bool) (*net.UDPConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		},
		deliver: func(pkt []byte) { got <- pkt },
		dnsIdle: time.Millisecond,
	}
	defer f.close()
	app := netip.MustParseAddrPort("198.18.0.1:5000")
	dst := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	p, _ := packet.Parse(packet.BuildUDP(app, dst, []byte("hi")))
	f.send(&p)
	f.send(&p)
	for range 2 {
		select {
		case b := <-got:
			r, err := packet.Parse(b)
			if err != nil || r.Src() != dst || r.Dst() != app || string(r.Payload()) != "re:hi" || !r.VerifyChecksums() {
				t.Fatalf("%v %v -> %v %q", err, r.Src(), r.Dst(), r.Payload())
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no reply")
		}
	}
	if f.len() != 1 || f.Sent.Load() != 2 || f.Recv.Load() != 2 {
		t.Fatalf("socks %d sent %d recv %d", f.len(), f.Sent.Load(), f.Recv.Load())
	}
	// Not DNS only: kept past the DNS idle time, closed past the idle one.
	f.sweep(time.Now().Add(time.Second))
	if f.len() != 1 {
		t.Fatal("swept early")
	}
	f.sweep(time.Now().Add(2 * time.Minute))
	if f.len() != 0 {
		t.Fatal("not swept")
	}
	f.close()
	f.send(&p)
	if f.Dropped.Load() != 1 {
		t.Fatal("sent after close")
	}
}
