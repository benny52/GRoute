package tgws

import (
	"context"
	"crypto/cipher"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Routes a connection can take to Telegram, best first.
const (
	RouteWS      = "ws"         // WebSocket, the name sent as it is
	RouteFronted = "ws-fronted" // WebSocket with another name in TLS
	RouteVPN     = "vpn"        // TCP to the data center through HyRoute's VPN
	RouteTCP     = "tcp"        // TCP to the data center, direct
)

// Config is the bridge's setup.
type Config struct {
	// Redirect: the address each data center's WebSocket endpoints are
	// reached at (nil: DefaultRedirect). A data center without one goes by
	// the fallbacks.
	Redirect map[int]netip.Addr
	// PoolSize: WebSocket connections kept open per data center (and
	// media), so a new Telegram connection does not wait for TLS
	// (0: 2; negative: none).
	PoolSize int
	// Dial opens direct TCP connections (nil: a net.Dialer).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// VPN opens a TCP connection to a data center through HyRoute's VPN
	// (nil, or an error: that fallback is skipped).
	VPN func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// Roots verify the WebSocket certificates (nil: the system's).
	Roots *x509.CertPool
	Log   *slog.Logger
	// NoFronting skips the fronted WebSocket (tests).
	NoFronting bool
}

// Stats are the bridge's counters.
type Stats struct {
	Active int64            `json:"active"`
	Total  int64            `json:"total"`
	Bad    int64            `json:"bad"`    // inits that did not decode (a wrong secret)
	Failed int64            `json:"failed"` // no route opened
	Routes map[string]int64 `json:"routes"`
	Up     int64            `json:"up"`   // bytes to Telegram
	Down   int64            `json:"down"` // bytes from it
	// LastRoute: the route of the latest connection; LastError: why the
	// latest one that failed did ("" when the latest one opened).
	LastRoute string `json:"lastRoute"`
	LastError string `json:"lastError,omitempty"`
}

// Bridge carries MTProto connections to Telegram.
type Bridge struct {
	cfg  Config
	pool *wsPool

	fronted atomic.Bool // the fronted name worked last
	active  atomic.Int64
	total   atomic.Int64
	bad     atomic.Int64
	failed  atomic.Int64
	up      atomic.Int64
	down    atomic.Int64

	mu        sync.Mutex
	routes    map[string]int64
	lastRoute string
	lastError string
	tcpAfter  map[netip.AddrPort]time.Time // direct TCP backoff
	tcpFails  map[netip.AddrPort]int
}

// New makes a bridge; Close ends its pool.
func New(cfg Config) *Bridge {
	if cfg.Redirect == nil {
		cfg.Redirect = DefaultRedirect()
	}
	if cfg.PoolSize == 0 {
		cfg.PoolSize = 2
	}
	if cfg.Dial == nil {
		var d net.Dialer
		cfg.Dial = d.DialContext
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	b := &Bridge{cfg: cfg, routes: map[string]int64{}, tcpAfter: map[netip.AddrPort]time.Time{}, tcpFails: map[netip.AddrPort]int{}}
	b.pool = newPool(b)
	return b
}

// Warm opens the pool's connections ahead of the first client.
func (b *Bridge) Warm() {
	for dc := range b.cfg.Redirect {
		for _, media := range []bool{false, true} {
			b.pool.refill(poolKey{dc: dc, media: media})
		}
	}
}

// Close closes the pooled connections; connections being carried end
// with their clients.
func (b *Bridge) Close() { b.pool.close() }

// Stats returns the counters.
func (b *Bridge) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := make(map[string]int64, len(b.routes))
	for k, v := range b.routes {
		r[k] = v
	}
	return Stats{Active: b.active.Load(), Total: b.total.Load(), Bad: b.bad.Load(), Failed: b.failed.Load(),
		Routes: r, Up: b.up.Load(), Down: b.down.Load(), LastRoute: b.lastRoute, LastError: b.lastError}
}

func (b *Bridge) note(route string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.lastError = err.Error()
		return
	}
	b.routes[route]++
	b.lastRoute, b.lastError = route, ""
}

// upstream is the connection to Telegram.
type upstream interface {
	send(parts ...[]byte) error
	recv() ([]byte, error)
	close()
}

type wsUp struct{ w *wsConn }

func (u wsUp) send(parts ...[]byte) error { return u.w.Send(parts...) }
func (u wsUp) recv() ([]byte, error)      { return u.w.Recv() }
func (u wsUp) close()                     { u.w.Close() }

type tcpUp struct {
	c   net.Conn
	buf []byte
}

func (u *tcpUp) send(parts ...[]byte) error {
	for _, p := range parts {
		if _, err := u.c.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func (u *tcpUp) recv() ([]byte, error) {
	n, err := u.c.Read(u.buf)
	if n > 0 {
		return u.buf[:n], nil
	}
	return nil, err
}

func (u *tcpUp) close() { u.c.Close() }

// errNoRoute: every route failed.
var errNoRoute = errors.New("Telegram недоступен ни через WebSocket, ни напрямую")

// Serve carries one client connection whose first bytes are an
// obfuscated MTProto init with secret (nil: Telegram's own connection,
// no proxy secret). It returns when either side closes.
func (b *Bridge) Serve(ctx context.Context, client net.Conn, secret []byte) {
	defer client.Close()
	b.active.Add(1)
	defer b.active.Add(-1)
	b.total.Add(1)
	init := make([]byte, initLen)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(client, init); err != nil {
		return
	}
	client.SetReadDeadline(time.Time{})
	h, ok := ReadHello(init, secret)
	if !ok {
		b.bad.Add(1)
		b.cfg.Log.Warn("tgws: an init that does not decode (a wrong secret?)")
		// Read a little, as a server that did not understand would.
		client.SetReadDeadline(time.Now().Add(10 * time.Second))
		io.CopyN(io.Discard, client, 64<<10)
		return
	}
	rinit, tgEnc, tgDec := relayInit(h.Proto, dcIndex(h.DC, h.Media, h.Test))
	up, route, err := b.open(ctx, h, rinit)
	if err != nil {
		b.failed.Add(1)
		b.note("", err)
		b.cfg.Log.Warn("tgws: no route to Telegram", "dc", h.DC, "media", h.Media, "err", err)
		return
	}
	b.note(route, nil)
	b.cfg.Log.Debug("tgws: connection", "dc", h.DC, "media", h.Media, "route", route)
	b.pump(client, up, h, tgEnc, tgDec, route == RouteWS || route == RouteFronted)
}

// open takes the first route that opens, sending the relay init on it.
func (b *Bridge) open(ctx context.Context, h Hello, rinit []byte) (upstream, string, error) {
	var errs []error
	if _, ok := b.cfg.Redirect[h.DC]; ok {
		key := poolKey{dc: h.DC, media: h.Media, test: h.Test}
		w, route, err := b.pool.get(ctx, key)
		if err == nil {
			if err = w.Send(rinit); err == nil {
				return wsUp{w}, route, nil
			}
			w.c.Close()
		}
		errs = append(errs, err)
	}
	dst, ok := directAddr(h.DC, h.Test)
	if !ok {
		errs = append(errs, fmt.Errorf("неизвестный дата-центр %d", h.DC))
		return nil, "", errors.Join(append([]error{errNoRoute}, errs...)...)
	}
	if b.cfg.VPN != nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err := b.cfg.VPN(cctx, dst)
		cancel()
		if err == nil {
			if _, err = c.Write(rinit); err == nil {
				return &tcpUp{c: c, buf: make([]byte, 64<<10)}, RouteVPN, nil
			}
			c.Close()
		}
		errs = append(errs, fmt.Errorf("через VPN: %w", err))
	}
	c, err := b.dialTCP(ctx, dst)
	if err == nil {
		if _, err = c.Write(rinit); err == nil {
			return &tcpUp{c: c, buf: make([]byte, 64<<10)}, RouteTCP, nil
		}
		c.Close()
	}
	errs = append(errs, fmt.Errorf("напрямую: %w", err))
	return nil, "", errors.Join(append([]error{errNoRoute}, errs...)...)
}

// dialTCP connects to a data center directly, backing off from one that
// failed (Telegram retries at once; a blocked address need not be tried
// each time).
func (b *Bridge) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	b.mu.Lock()
	after := b.tcpAfter[dst]
	b.mu.Unlock()
	if time.Now().Before(after) {
		return nil, errors.New("недавно не соединялось, следующая попытка позже")
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := b.cfg.Dial(cctx, "tcp", dst.String())
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.tcpFails[dst]++
		d := min(30*time.Second<<min(b.tcpFails[dst]-1, 7), time.Hour)
		b.tcpAfter[dst] = time.Now().Add(d)
		return nil, err
	}
	delete(b.tcpFails, dst)
	delete(b.tcpAfter, dst)
	return c, nil
}

// pump re-keys both ways until one side ends.
func (b *Bridge) pump(client net.Conn, up upstream, h Hello, tgEnc, tgDec cipher.Stream, frames bool) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			up.close()
			client.Close()
		})
	}
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // Telegram → client
		defer wg.Done()
		defer stop()
		for {
			p, err := up.recv()
			if len(p) > 0 {
				tgDec.XORKeyStream(p, p)
				h.enc.XORKeyStream(p, p)
				if _, werr := client.Write(p); werr != nil {
					return
				}
				b.down.Add(int64(len(p)))
			}
			if err != nil {
				return
			}
		}
	}()
	// client → Telegram
	var sp *splitter
	if frames {
		sp = newSplitter(h.Proto)
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := client.Read(buf)
		if n > 0 {
			plain := make([]byte, n)
			h.dec.XORKeyStream(plain, buf[:n])
			enc := make([]byte, n)
			tgEnc.XORKeyStream(enc, plain)
			b.up.Add(int64(n))
			var serr error
			if sp != nil {
				if parts := sp.add(enc, plain); len(parts) > 0 {
					serr = up.send(parts...)
				}
			} else {
				serr = up.send(enc)
			}
			if serr != nil {
				break
			}
		}
		if err != nil {
			if sp != nil {
				if rest := sp.flush(); rest != nil {
					up.send(rest)
				}
			}
			break
		}
	}
	stop()
	wg.Wait()
}
