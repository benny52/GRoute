package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// CheckStep is one line of a profile check.
type CheckStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Skip   bool   `json:"skip"`
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

type CheckResult struct {
	Profile    string      `json:"profile"`
	OK         bool        `json:"ok"`
	Steps      []CheckStep `json:"steps"`
	ExternalIP string      `json:"externalIP"`
	LatencyMs  int64       `json:"latencyMs"`
	ResponseMs *int64      `json:"responseMs,omitempty"`
}

// Check targets (variables for tests): IP-echo services over HTTPS, a
// host for the latency CONNECT, a DNS server for the UDP probe.
var (
	ipServices    = []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	latencyTarget = socks5.Addr{Host: "one.one.one.one", Port: 443}
	dnsProbe      = socks5.Addr{IP: netip.MustParseAddr("1.1.1.1"), Port: 53}
)

// CheckProfile starts the profile (or uses its running Hysteria), then
// checks TCP through it, the external IP, latency and UDP.
func (c *Controller) CheckProfile(id string) (CheckResult, error) {
	return c.checkProfile(context.Background(), id)
}

// Register the batch before issuing its first check. A cancel arriving
// ahead of a queued check (or from a previous window) cannot miss it.
func (c *Controller) BeginCheckBatch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checkBatchCancel != nil {
		c.checkBatchCancel()
	}
	c.checkBatchID++
	c.checkBatchCtx, c.checkBatchCancel = context.WithCancel(context.Background())
	return c.checkBatchID
}

func (c *Controller) EndCheckBatch(token uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token == c.checkBatchID && c.checkBatchCancel != nil {
		c.checkBatchCancel()
		c.checkBatchCtx, c.checkBatchCancel = nil, nil
	}
}

func (c *Controller) CheckBatchProfile(token uint64, id string) (CheckResult, error) {
	c.mu.Lock()
	ctx, current := c.checkBatchCtx, c.checkBatchID
	c.mu.Unlock()
	if token != current || ctx == nil {
		return CheckResult{}, context.Canceled
	}
	res, err := c.checkProfile(ctx, id)
	if ctx.Err() != nil {
		return CheckResult{}, ctx.Err()
	}
	return res, err
}

func (c *Controller) checkProfile(ctx context.Context, id string) (CheckResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	p, err := c.Profile(id)
	if err != nil {
		return CheckResult{}, err
	}
	res := CheckResult{Profile: p.Name}
	ep, release := c.acquire(p)
	defer release()

	// 1. Hysteria (Xray for VLESS) connects. Xray is up once a request
	// went through the server, and the first may take a few tries.
	start := time.Now()
	limit, core := 20*time.Second, p.EngineName()
	if p.IsVLESS() {
		limit = 45 * time.Second
	}
	st, err := waitConnected(ctx, ep, limit, core)
	step := CheckStep{Name: "Подключение к серверу через " + core, Ms: time.Since(start).Milliseconds()}
	if err != nil {
		step.Detail = err.Error()
		res.Steps = append(res.Steps, step)
		res.Steps = append(res.Steps, CheckStep{Name: "Открытие TCP до " + latencyTarget.String(), Skip: true, Detail: "пропущено"})
		return res, nil
	}
	step.OK, step.Detail = true, "подключено"
	res.Steps = append(res.Steps, step)

	// 2. TCP: a CONNECT through the tunnel (latency) and HTTPS for the
	// external IP.
	// Check dials are Quiet: a check destination that fails must not count
	// against the server in its groups (a routing endpoint is reused).
	dialCtx, cancel := context.WithTimeout(tunnels.Quiet(ctx), 15*time.Second)
	t0 := time.Now()
	conn, err := ep.Dial(dialCtx, latencyTarget)
	cancel()
	step = CheckStep{Name: "Открытие TCP до " + latencyTarget.String(), Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		step.Detail = "соединение через SOCKS5 не открылось: " + err.Error()
		res.Steps = append(res.Steps, step)
		return res, nil
	}
	conn.Close()
	res.LatencyMs = step.Ms
	step.OK, step.Detail = true, "Локальный SOCKS5 подтвердил запрос на соединение через выбранный профиль."
	res.Steps = append(res.Steps, step)

	t0 = time.Now()
	client := checkHTTPClient(ctx, ep)
	defer client.CloseIdleConnections()
	ip, target, err := externalIP(ctx, client)
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	step = CheckStep{Name: "Внешний IP через туннель", Ms: time.Since(t0).Milliseconds()}
	if err != nil {
		step.Detail = err.Error()
	} else {
		step.OK, step.Detail, res.ExternalIP = true, ip, ip
	}
	res.Steps = append(res.Steps, step)

	step = CheckStep{Name: "Отклик после подключения", Skip: true, Detail: "Сервис внешнего IP недоступен."}
	if target != nil {
		ms, err := responseTime(ctx, client.Transport, target)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err != nil {
			step.Detail = fmt.Sprintf("Не удалось измерить отклик %s: %v", target.Host, err)
		} else {
			res.ResponseMs = &ms
			step.OK, step.Skip, step.Ms = true, false, ms
			step.Detail = fmt.Sprintf("Повторный запрос к %s. От готового соединения до заголовков ответа.", target.Host)
		}
	}
	res.Steps = append(res.Steps, step)

	// 3. UDP: a DNS query to 1.1.1.1 through UDP ASSOCIATE.
	step = CheckStep{Name: "UDP через туннель"}
	if !st.UDPEnabled {
		step.Skip, step.Detail = true, "сервер запретил UDP: UDP-правила с этим профилем будут отклоняться"
	} else {
		t0 = time.Now()
		err := udpProbe(ctx, ep)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		step.Ms = time.Since(t0).Milliseconds()
		if err != nil {
			step.Detail = err.Error()
		} else {
			step.OK, step.Detail = true, fmt.Sprintf("DNS-запрос к 1.1.1.1 получил ответ за %d мс", step.Ms)
		}
	}
	res.Steps = append(res.Steps, step)
	res.OK = true
	for _, s := range res.Steps {
		if !s.OK && !s.Skip {
			res.OK = false
		}
	}
	c.Log.Info("profile check", "profile", p.Name, "ok", res.OK, "latencyMs", res.LatencyMs)
	return res, nil
}

// acquire returns an endpoint for p: the routing session's when connected
// (it excludes the server from interception), otherwise a standalone
// Hysteria.
func (c *Controller) acquire(p hysteria.Profile) (*tunnels.Endpoint, func()) {
	c.mu.Lock()
	sess := c.sess
	if sess == nil && c.checkMgr == nil {
		f := c.Runners
		if f == nil {
			base := c.Base
			base.Redactor = c.Redactor
			f = session.RunnerFactory(base)
		}
		c.checkMgr = &tunnels.Manager{New: f, Log: c.Log, LogLine: c.hysteriaLine}
	}
	mgr := c.checkMgr
	c.mu.Unlock()
	if sess != nil {
		return sess.Acquire(p)
	}
	return mgr.Acquire(p)
}

func waitConnected(ctx context.Context, ep *tunnels.Endpoint, timeout time.Duration, core string) (hysteria.Status, error) {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		st := ep.Status()
		switch {
		case st.State == hysteria.Connected:
			return st, nil
		case st.State == hysteria.Failed && st.Message != "":
			return st, errors.New(st.Message)
		case time.Now().After(deadline):
			if st.Message != "" {
				return st, errors.New(st.Message)
			}
			if core != "Hysteria" {
				return st, fmt.Errorf("%s: сервер не ответил за %d с", core, int(timeout.Seconds()))
			}
			return st, fmt.Errorf("Hysteria не подключилась за %d с: сервер не отвечает (порт, obfs-пароль или блокировка UDP)", int(timeout.Seconds()))
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-tick.C:
		}
	}
}

func checkHTTPClient(ctx context.Context, ep *tunnels.Endpoint) *http.Client {
	tr := &http.Transport{
		DialContext: func(transportCtx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var pn uint16
			fmt.Sscan(port, &pn)
			// net/http may let a dial outlive its request to reuse the
			// connection. This probe also ends when the batch is cancelled.
			dialCtx, cancel := context.WithCancel(transportCtx)
			defer cancel()
			stop := context.AfterFunc(ctx, cancel)
			defer stop()
			return ep.Dial(tunnels.Quiet(dialCtx), socks5.Addr{Host: host, Port: pn})
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 12 * time.Second}
}

func externalIP(ctx context.Context, cl *http.Client) (string, *url.URL, error) {
	var last error
	for _, u := range ipServices {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			last = err
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if _, err := netip.ParseAddr(ip); resp.StatusCode == 200 && err == nil {
			return ip, resp.Request.URL, nil
		}
		last = fmt.Errorf("%s ответил %s", u, resp.Status)
	}
	return "", nil, fmt.Errorf("HTTPS через туннель не прошёл: %v", last)
}

// Reuse the IP service and its transport. If a server closed its idle
// connection, GotConn starts the timer after the replacement's TLS handshake.
func responseTime(parent context.Context, tr http.RoundTripper, target *url.URL) (int64, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var start atomic.Pointer[time.Time]
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		now := time.Now()
		start.Store(&now)
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	end := time.Now()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ready := start.Load()
	if ready == nil {
		return 0, errors.New("неизвестно время установки соединения")
	}
	return end.Sub(*ready).Milliseconds(), nil
}

func udpProbe(parent context.Context, ep *tunnels.Endpoint) error {
	ctx, cancel := context.WithTimeout(tunnels.Quiet(parent), 8*time.Second)
	defer cancel()
	a, err := ep.UDPAssociate(ctx)
	if err != nil {
		return fmt.Errorf("UDP ASSOCIATE не удался: %v", err)
	}
	defer a.Close()
	var idb [2]byte
	rand.Read(idb[:])
	id := uint16(idb[0])<<8 | uint16(idb[1])
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	q, _ := msg.Pack()
	dst := dnsProbe
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := a.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) == nil && m.ID == id {
				done <- nil
				return
			}
		}
	}()
	for try := 0; try < 3; try++ {
		if err := a.WriteTo(q, dst); err != nil {
			return fmt.Errorf("отправка не удалась: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if err != nil {
				return fmt.Errorf("ответ не получен: %v", err)
			}
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("ответа на DNS-запрос через UDP нет за 6 с: UDP через сервер не проходит")
}
