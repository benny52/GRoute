package zapret

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Checks are the addresses a target is checked with. DPI blocks in two
// ways: it stalls or resets the TLS handshake, or (TSPU) lets it and the
// first ~16 KB through and then freezes the connection. So each target has
// a page well over that (the main pages) and the check reads up to
// maxBody of every answer; googlevideo.com, where the video comes from,
// only serves small answers without a signed link but shows a blocked
// handshake.
func Checks(t Target, sites []string) []string {
	switch t {
	case YouTube:
		return []string{"https://www.youtube.com/", "https://redirector.googlevideo.com/report_mapping", "https://i.ytimg.com/generate_204"}
	case Discord:
		return []string{"https://discord.com/", "https://gateway.discord.gg/", "https://cdn.discordapp.com/embed/avatars/0.png"}
	}
	var out []string
	for _, s := range sites {
		if len(out) == 5 {
			break // the first few say enough
		}
		out = append(out, "https://"+s+"/")
	}
	return out
}

// CheckTimeout bounds one address's check.
var CheckTimeout = 7 * time.Second

// maxBody: how much of an answer the check reads. Past the ~16 KB after
// which TSPU freezes a connection; a shorter answer is read to its end.
const maxBody = 64 << 10

// Result of checking a target.
type Result struct {
	OK      bool
	Failed  []string // the addresses that failed, with the reason
	Elapsed time.Duration
}

// Check checks every address of urls at once with a client that dials
// directly (dial: nil = net.Dialer). The target works when all answer.
func Check(ctx context.Context, urls []string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) Result {
	if dial == nil {
		dial = (&net.Dialer{Timeout: CheckTimeout}).DialContext
	}
	tr := &http.Transport{
		DialContext:         dial,
		TLSHandshakeTimeout: CheckTimeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		Proxy:               nil,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: CheckTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	var mu sync.Mutex
	var wg sync.WaitGroup
	res := Result{OK: len(urls) > 0}
	for _, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := checkOne(ctx, client, u); err != nil {
				mu.Lock()
				res.OK = false
				res.Failed = append(res.Failed, fmt.Sprintf("%s: %v", strings.TrimPrefix(u, "https://"), err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	res.Elapsed = time.Since(start)
	return res
}

func checkOne(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := client.Do(req)
	if err != nil {
		return shortErr(err)
	}
	defer resp.Body.Close()
	if _, err := io.CopyN(io.Discard, resp.Body, maxBody); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("ответ оборвался: %w", shortErr(err))
	}
	return nil
}

func shortErr(err error) error {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return errors.New("нет ответа")
	case strings.Contains(err.Error(), "reset"):
		return errors.New("соединение сброшено")
	case strings.Contains(err.Error(), "EOF"):
		return errors.New("соединение оборвано")
	}
	return err
}
