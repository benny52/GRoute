package tgws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"sync"
)

// Proxy is a local MTProto proxy (with a secret, as Telegram's proxy
// settings take one) whose connections go over the bridge.
type Proxy struct {
	Bridge *Bridge
	Secret []byte // 16 bytes

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]bool
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSecret makes a proxy secret.
func NewSecret() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ParseSecret reads a secret: 32 hex digits, a "dd" in front allowed.
func ParseSecret(s string) ([]byte, error) {
	if len(s) == 34 && (s[:2] == "dd" || s[:2] == "DD") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("секрет — 32 шестнадцатеричные цифры")
	}
	return b, nil
}

// Link is the tg://proxy link that adds the proxy to Telegram. The "dd"
// in front of the secret makes Telegram pad its packets (the padded
// intermediate transport).
func Link(host string, port int, secret []byte) string {
	q := url.Values{}
	q.Set("server", host)
	q.Set("port", strconv.Itoa(port))
	q.Set("secret", "dd"+hex.EncodeToString(secret))
	return "tg://proxy?" + q.Encode()
}

// Listen starts the proxy on addr («127.0.0.1:1443»).
func (p *Proxy) Listen(addr string) error {
	if len(p.Secret) != 16 {
		return errors.New("tgws: a 16-byte secret is needed")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.ln, p.conns = ln, map[net.Conn]bool{}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.mu.Unlock()
	p.wg.Add(1)
	go p.serve(ln)
	return nil
}

// Addr is the listening address (nil before Listen).
func (p *Proxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return nil
	}
	return p.ln.Addr()
}

func (p *Proxy) serve(ln net.Listener) {
	defer p.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		p.mu.Lock()
		if p.conns == nil {
			p.mu.Unlock()
			c.Close()
			return
		}
		p.conns[c] = true
		p.mu.Unlock()
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.Bridge.Serve(p.ctx, c, p.Secret)
			p.mu.Lock()
			delete(p.conns, c)
			p.mu.Unlock()
		}()
	}
}

// Close stops listening and ends the connections.
func (p *Proxy) Close() error {
	p.mu.Lock()
	ln, conns := p.ln, p.conns
	p.ln, p.conns = nil, nil
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	for c := range conns {
		c.Close()
	}
	p.wg.Wait()
	return err
}
