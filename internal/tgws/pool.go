package tgws

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// The pool keeps WebSocket connections open per data center, so a new
// Telegram connection takes one at once instead of waiting for TCP and
// TLS. A connection is used once; an idle one older than poolMaxAge is
// dropped (the server may have closed it).

var poolMaxAge = 60 * time.Second // a test hook

type poolKey struct {
	dc          int
	media, test bool
}

type pooled struct {
	w     *wsConn
	at    time.Time
	route string
}

type wsPool struct {
	b         *Bridge
	mu        sync.Mutex
	idle      map[poolKey][]pooled
	refilling map[poolKey]bool
	fails     map[poolKey]int
	after     map[poolKey]time.Time
	closed    bool
}

func newPool(b *Bridge) *wsPool {
	return &wsPool{b: b, idle: map[poolKey][]pooled{}, refilling: map[poolKey]bool{}, fails: map[poolKey]int{}, after: map[poolKey]time.Time{}}
}

// get returns a pooled connection or opens one, and tops the pool up.
func (p *wsPool) get(ctx context.Context, k poolKey) (*wsConn, string, error) {
	p.mu.Lock()
	for len(p.idle[k]) > 0 {
		e := p.idle[k][0]
		p.idle[k] = p.idle[k][1:]
		if time.Since(e.at) < poolMaxAge {
			p.mu.Unlock()
			p.refill(k)
			return e.w, e.route, nil
		}
		go e.w.c.Close()
	}
	p.mu.Unlock()
	w, route, err := p.b.connect(ctx, k)
	p.refill(k)
	return w, route, err
}

// refill opens what the pool lacks for k, in the background.
func (p *wsPool) refill(k poolKey) {
	size := p.b.cfg.PoolSize
	if size <= 0 {
		return
	}
	p.mu.Lock()
	if p.closed || p.refilling[k] || time.Now().Before(p.after[k]) {
		p.mu.Unlock()
		return
	}
	need := size - len(p.idle[k])
	if need <= 0 {
		p.mu.Unlock()
		return
	}
	p.refilling[k] = true
	p.mu.Unlock()
	go func() {
		ok := 0
		for range need {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			w, route, err := p.b.connect(ctx, k)
			cancel()
			if err != nil {
				break
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				w.c.Close()
				break
			}
			p.idle[k] = append(p.idle[k], pooled{w: w, at: time.Now(), route: route})
			p.mu.Unlock()
			ok++
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.refilling[k] = false
		if ok > 0 {
			delete(p.fails, k)
			delete(p.after, k)
			return
		}
		p.fails[k]++
		p.after[k] = time.Now().Add(min(time.Second<<min(p.fails[k]-1, 12), time.Hour))
	}()
}

func (p *wsPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for k, es := range p.idle {
		for _, e := range es {
			e.w.c.Close()
		}
		delete(p.idle, k)
	}
}

// connect opens a WebSocket connection for k: each of its names, with the
// name sent as it is and fronted (the way that worked last first).
func (b *Bridge) connect(ctx context.Context, k poolKey) (*wsConn, string, error) {
	addr, ok := b.cfg.Redirect[k.dc]
	if !ok {
		return nil, "", errors.New("нет адреса WebSocket для этого дата-центра")
	}
	path := "/apiws"
	if k.test {
		path = "/apiws_test"
	}
	modes := []bool{false, true}
	if b.fronted.Load() {
		modes = []bool{true, false}
	}
	if b.cfg.NoFronting {
		modes = []bool{false}
	}
	var errs []error
	for _, host := range wsHosts(k.dc, k.media) {
		for _, fronted := range modes {
			t := wsTarget{Addr: net.JoinHostPort(addr.String(), "443"), Host: host, Path: path, Roots: b.cfg.Roots}
			route := RouteWS
			if fronted {
				t.SNI, route = FrontingSNI, RouteFronted
			}
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			w, err := dialWS(cctx, b.cfg.Dial, t)
			cancel()
			if err == nil {
				b.fronted.Store(fronted)
				return w, route, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				return nil, "", errors.Join(errs...)
			}
		}
	}
	return nil, "", errors.Join(errs...)
}
