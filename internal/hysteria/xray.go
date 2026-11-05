package hysteria

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// A VLESS profile runs in xray.exe (internal/vless writes its config). The
// supervisor runs it like Hysteria, but Xray reports no connection to the
// server: it connects per request. So a run is up once its SOCKS5 port
// answers and an HTTP request goes through the server (watchVLESS), and
// is restarted when such requests stop going through.

// DefaultProbeURLs answer any request with 204 and no body.
var DefaultProbeURLs = []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"}

// Test hooks.
var (
	vlessProbeTimeout = 10 * time.Second
	vlessProbeEvery   = time.Minute
	vlessRetryEvery   = 3 * time.Second
)

const (
	// vlessFirstTries: probes before a new run counts as failed (the first
	// connection to a server may be slow); vlessLostAfter: failed probes
	// in a row that end a run that was up.
	vlessFirstTries = 3
	vlessLostAfter  = 2
)

// coreName names the program this profile runs in.
func (s *Supervisor) coreName() string {
	if s.Profile.IsVLESS() {
		return "Xray"
	}
	return "Hysteria"
}

// watchVLESS waits for Xray's SOCKS5 port, calls up after the first
// request that went through the server, and keeps checking every
// vlessProbeEvery. A run that never gets a request through, or stops
// getting them through, is restarted with the reason (Xray's last warning
// says it best).
func (s *Supervisor) watchVLESS(ctx context.Context, addr string, kick chan restart, lastWarn *atomic.Pointer[string], up func()) {
	send := func(r restart) {
		if ctx.Err() == nil {
			select {
			case kick <- r:
			default:
			}
		}
	}
	if !waitListening(ctx, addr, 15*time.Second) {
		send(restart{ErrPortBusy, "Xray не открыла локальный порт SOCKS5, перезапуск"})
		return
	}
	c := s.SOCKS()
	connected, fails := false, 0
	for {
		err := s.probeVLESS(ctx, c)
		if ctx.Err() != nil {
			return
		}
		wait := vlessRetryEvery
		if err == nil {
			fails = 0
			if !connected {
				connected = true
				up()
			}
			wait = vlessProbeEvery
		} else {
			fails++
			if !connected && fails >= vlessFirstTries || connected && fails >= vlessLostAfter {
				warn := ""
				if w := lastWarn.Load(); w != nil {
					warn = *w
				}
				kind, msg := ClassifyXray(err, warn)
				if connected {
					// It worked with these settings: no reason for the
					// long wait of a refused password.
					msg = "Потеряна связь с сервером: " + msg
					if kind == ErrAuth {
						kind = ErrOther
					}
				}
				send(restart{kind, msg})
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// probeVLESS sends an HTTP request through the tunnel to each probe URL
// until one answers.
func (s *Supervisor) probeVLESS(ctx context.Context, c socks5.Client) error {
	urls := s.ProbeURLs
	if len(urls) == 0 {
		urls = DefaultProbeURLs
	}
	var first error
	for _, u := range urls {
		err := probeHTTP(ctx, c, u)
		if err == nil || ctx.Err() != nil {
			return err
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// errNoHTTP: the tunnel took the connection, but no HTTP answer came back
// through it.
var errNoHTTP = errors.New("no HTTP answer through the tunnel")

// probeHTTP is one plain HTTP GET through SOCKS5 c. Any HTTP status line
// counts: it came from the far side of the server.
func probeHTTP(ctx context.Context, c socks5.Client, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return fmt.Errorf("probe URL %q", rawURL)
	}
	port := 80
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return fmt.Errorf("probe URL %q", rawURL)
		}
	}
	dst := socks5.Addr{Host: u.Hostname(), Port: uint16(port)}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		dst = socks5.Addr{IP: ip, Port: uint16(port)}
	}
	pctx, cancel := context.WithTimeout(ctx, vlessProbeTimeout)
	defer cancel()
	conn, err := c.Connect(pctx, dst)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(pctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	path := u.RequestURI()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HyRoute\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/") {
		if err == nil {
			return errNoHTTP
		}
		return fmt.Errorf("%w: %v", errNoHTTP, err)
	}
	return nil
}

// ClassifyXray explains a failed probe: by Xray's last warning when it
// has one, else by the probe's error.
func ClassifyXray(probeErr error, lastWarn string) (ErrorKind, string) {
	text := lastWarn
	if text == "" && probeErr != nil {
		text = probeErr.Error()
	}
	e := strings.ToLower(text)
	switch {
	case strings.Contains(e, "x509") || strings.Contains(e, "certificate") || strings.Contains(e, "pinned"):
		return ErrTLS, "Сертификат сервера не прошёл проверку: проверьте sni или закрепите сертификат (pinSHA256)"
	case strings.Contains(e, "reality"):
		return ErrAuth, "REALITY не прошёл: проверьте публичный ключ (pbk), shortId и sni"
	case strings.Contains(e, "refused"):
		return ErrTimeout, "Сервер отклонил подключение: на этом адресе и порту ничего не слушает"
	case strings.Contains(e, "timeout") || strings.Contains(e, "deadline") || strings.Contains(e, "timed out"):
		return ErrTimeout, "Сервер не отвечает: проверьте адрес и порт"
	case strings.Contains(e, "no such host") || strings.Contains(e, "lookup "):
		return ErrTimeout, "Не удалось разрешить имя сервера"
	case errors.Is(probeErr, errNoHTTP) || strings.Contains(e, "eof") || strings.Contains(e, "reset") || strings.Contains(e, "closed"):
		// A wrong ID looks the same to the client as a server that drops
		// connections: no auth error, no long wait.
		return ErrOther, "Сервер не пропускает трафик: проверьте UUID, flow, encryption и параметры транспорта"
	}
	return ErrOther, "Запрос через сервер не прошёл: " + text
}

// ParseXrayLine reads one line of Xray's output:
//
//	2026/11/05 10:51:23.123456 [Warning] core: Xray 26.10.31 started
//
// Lines without a level (the banner, "Failed to start: …") come back with
// Level "raw".
func ParseXrayLine(line string) LogLine {
	l := LogLine{Raw: line, Level: "raw", Msg: line}
	rest := line
	if i := strings.Index(rest, " ["); i >= 19 && i <= 26 && rest[4] == '/' {
		for _, layout := range []string{"2006/01/02 15:04:05.000000", "2006/01/02 15:04:05"} {
			if t, err := time.ParseInLocation(layout, rest[:i], time.Local); err == nil {
				l.Time = t
				break
			}
		}
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if j := strings.Index(rest, "] "); j > 1 {
			switch lvl := strings.ToLower(rest[1:j]); lvl {
			case "warning":
				l.Level = "warn"
			case "error", "info", "debug":
				l.Level = lvl
			default:
				return l
			}
			l.Msg = rest[j+2:]
		}
	}
	return l
}

// InterpretXray reports a line that ends the run: Xray could not start
// (its config, a busy port).
func InterpretXray(l LogLine) (Event, bool) {
	text, ok := strings.CutPrefix(l.Raw, "Failed to start:")
	if !ok || l.Level != "raw" {
		return Event{}, false
	}
	text = strings.TrimSpace(text)
	kind, msg := Classify(text)
	if kind != ErrPortBusy {
		kind, msg = ErrConfig, "Xray не запустилась: "+text
	}
	return Event{Fatal: true, Kind: kind, Message: msg}, true
}
