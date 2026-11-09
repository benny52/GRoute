package tgws

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Self-checks: the bridge asks Telegram for the first step of a key
// exchange (req_pq_multi: no account, no key needed) and checks the
// answer (resPQ with the same nonce). A WebSocket that does not answer
// makes connections skip it until a later check finds it answering again
// (no wait for a dead route on each connection); the fallback that answers
// is said.

// Health is the latest self-check.
type Health struct {
	At time.Time `json:"at"`
	// WS: Telegram answered over WebSocket; WSRoute: ws or ws-fronted;
	// WSMillis: how long the answer took; WSError: why not.
	WS       bool   `json:"ws"`
	WSRoute  string `json:"wsRoute,omitempty"`
	WSMillis int64  `json:"wsMillis,omitempty"`
	WSError  string `json:"wsError,omitempty"`
	// Fallback: the route that answered when WebSocket did not (vpn,
	// tcp; "" none or not checked); FallbackError: why none did.
	Fallback      string `json:"fallback,omitempty"`
	FallbackError string `json:"fallbackError,omitempty"`
}

// Health returns the latest self-check (nil before the first).
func (b *Bridge) Health() *Health { return b.health.Load() }

// Check runs a self-check and keeps its result: connections skip
// WebSocket while it does not answer.
func (b *Bridge) Check(ctx context.Context) Health {
	h := Health{At: time.Now()}
	dcs := make([]int, 0, len(b.cfg.Redirect))
	for dc := range b.cfg.Redirect {
		dcs = append(dcs, dc)
	}
	slices.Sort(dcs)
	var errs []error
	for _, dc := range dcs {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		start := time.Now()
		w, route, err := b.connect(cctx, poolKey{dc: dc})
		if err == nil {
			err = askPQ(cctx, wsUp{w}, dc)
			w.c.Close()
		}
		cancel()
		if err == nil {
			h.WS, h.WSRoute, h.WSMillis = true, route, time.Since(start).Milliseconds()
			break
		}
		errs = append(errs, fmt.Errorf("DC%d: %w", dc, err))
	}
	if len(dcs) > 0 {
		b.wsDown.Store(!h.WS)
	}
	if !h.WS {
		if len(errs) > 0 {
			h.WSError = errors.Join(errs...).Error()
		}
		h.Fallback, h.FallbackError = b.checkFallback(ctx)
	}
	b.health.Store(&h)
	return h
}

// checkFallback asks DC2 through the VPN, else directly.
func (b *Bridge) checkFallback(ctx context.Context) (string, string) {
	dst, _ := directAddr(2, false)
	var errs []error
	if b.cfg.VPN != nil {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		c, err := b.cfg.VPN(cctx, dst)
		if err == nil {
			err = askPQ(cctx, &tcpUp{c: c, buf: make([]byte, 4096)}, 2)
			c.Close()
		}
		cancel()
		if err == nil {
			return RouteVPN, ""
		}
		errs = append(errs, fmt.Errorf("через VPN: %w", err))
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := b.cfg.Dial(cctx, "tcp", dst.String())
	if err == nil {
		err = askPQ(cctx, &tcpUp{c: c, buf: make([]byte, 4096)}, 2)
		c.Close()
	}
	if err == nil {
		return RouteTCP, ""
	}
	errs = append(errs, fmt.Errorf("напрямую: %w", err))
	return "", errors.Join(errs...).Error()
}

// askPQ sends req_pq_multi to data center dc over up and checks the
// answer.
func askPQ(ctx context.Context, up upstream, dc int) error {
	if dl, ok := ctx.Deadline(); ok {
		switch u := up.(type) {
		case wsUp:
			u.w.c.SetDeadline(dl)
		case *tcpUp:
			u.c.SetDeadline(dl)
		}
	}
	rinit, enc, dec := relayInit(ProtoIntermediate, dcIndex(dc, false, false))
	var nonce [16]byte
	rand.Read(nonce[:])
	msg := make([]byte, 0, 44)
	msg = binary.LittleEndian.AppendUint32(msg, 40)
	msg = binary.LittleEndian.AppendUint64(msg, 0) // auth_key_id: none yet
	msg = binary.LittleEndian.AppendUint64(msg, uint64(time.Now().Unix())<<32|4)
	msg = binary.LittleEndian.AppendUint32(msg, 20)
	msg = binary.LittleEndian.AppendUint32(msg, 0xbe7e8ef1) // req_pq_multi
	msg = append(msg, nonce[:]...)
	enc.XORKeyStream(msg, msg)
	if err := up.send(rinit); err != nil {
		return err
	}
	if err := up.send(msg); err != nil {
		return err
	}
	var got []byte
	for {
		p, err := up.recv()
		if len(p) > 0 {
			dec.XORKeyStream(p, p)
			got = append(got, p...)
		}
		if len(got) >= 4 {
			n := int(binary.LittleEndian.Uint32(got))
			if n < 40 || n > 4096 {
				return fmt.Errorf("ответ не похож на Telegram (%d байт)", n)
			}
			if len(got) >= 4+n {
				a := got[4:]
				if binary.LittleEndian.Uint32(a[20:]) != 0x05162463 || !bytes.Equal(a[24:40], nonce[:]) {
					return errors.New("ответ не похож на Telegram")
				}
				return nil
			}
		}
		if err != nil {
			return fmt.Errorf("Telegram не ответил: %w", err)
		}
	}
}
