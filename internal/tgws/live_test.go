package tgws

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
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
				t.Fatalf("an answer of %d bytes (%+v)", n, b.Stats())
			}
			ans := tc.recv(t, n)
			if c := binary.LittleEndian.Uint32(ans[20:]); c != 0x05162463 || !bytes.Equal(ans[24:40], nonce[:]) {
				t.Fatalf("not resPQ: %x", ans[:min(len(ans), 48)])
			}
			st := b.Stats()
			if c.route != "" && st.Routes[c.route] != 1 {
				t.Fatalf("%+v", st)
			}
			t.Logf("%s: resPQ via %s", c.name, st.LastRoute)
		})
	}
}
