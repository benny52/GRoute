// Package release reads GitHub Releases (HyRoute's own and apernet/hysteria),
// compares versions and downloads assets with SHA256 verification.
package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // "sha256:<hex>" (GitHub fills it for new uploads)
}

// SHA256 returns the digest GitHub computed, or "".
func (a Asset) SHA256() string {
	if h, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
		return strings.ToLower(h)
	}
	return ""
}

type Release struct {
	Tag        string    `json:"tag_name"`
	Name       string    `json:"name"`
	Body       string    `json:"body"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Published  time.Time `json:"published_at"`
	Page       string    `json:"html_url"`
	Assets     []Asset   `json:"assets"`
}

func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Client talks to GitHub. API may be changed in tests.
type Client struct {
	HTTP      *http.Client
	API       string // default https://api.github.com
	UserAgent string
}

// The default client has no overall timeout: http.Client.Timeout also
// cuts off reading the body, and a package takes minutes on a slow line.
// Small requests (release lists, checksum files) end after
// requestTimeout; a download ends with its context or when no data comes
// for stallTimeout.
var (
	requestTimeout = 60 * time.Second
	stallTimeout   = 60 * time.Second
)

var errStalled = errors.New("сервер перестал присылать данные")

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{}
}

func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "HyRoute"
	}
	req.Header.Set("User-Agent", ua)
	if strings.Contains(url, "api.github.com") || (c.API != "" && strings.HasPrefix(url, c.API)) {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, errors.New("релизы не найдены (репозиторий приватный или релизов ещё нет)")
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return nil, errors.New("GitHub временно ограничил запросы, попробуйте позже")
		}
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	return resp, nil
}

// Releases lists the newest releases of owner/repo (drafts skipped).
func (c *Client) Releases(ctx context.Context, repo string) ([]Release, error) {
	return c.listReleases(ctx, repo, false)
}

// AllReleases also reads older pages, for repositories which publish
// multiple independently versioned products under different tags.
func (c *Client) AllReleases(ctx context.Context, repo string) ([]Release, error) {
	return c.listReleases(ctx, repo, true)
}

func (c *Client) listReleases(ctx context.Context, repo string, all bool) ([]Release, error) {
	list, err := listPages[Release](ctx, c, repo, "releases", 30, all)
	if err != nil {
		return nil, err
	}
	out := list[:0]
	for _, r := range list {
		if !r.Draft {
			out = append(out, r)
		}
	}
	return out, nil
}

// LatestStableTag finds the latest stable version of a module major line.
// Some Go modules publish tags without creating GitHub release objects.
func (c *Client) LatestStableTag(ctx context.Context, repo string, major int) (string, error) {
	type tag struct {
		Name string `json:"name"`
	}
	tags, err := listPages[tag](ctx, c, repo, "tags", 100, true)
	if err != nil {
		return "", err
	}
	var latest string
	for _, t := range tags {
		v, err := Parse(t.Name)
		if err == nil && fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch) == t.Name && v.Major == major && (latest == "" || Compare(t.Name, latest) > 0) {
			latest = t.Name
		}
	}
	if latest == "" {
		return "", fmt.Errorf("стабильных тегов v%d в %s не найдено", major, repo)
	}
	return latest, nil
}

func listPages[T any](ctx context.Context, c *Client, repo, resource string, perPage int, all bool) ([]T, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	api := c.API
	if api == "" {
		api = "https://api.github.com"
	}
	var out []T
	for page := 1; ; page++ {
		url := api + "/repos/" + repo + "/" + resource + "?per_page=" + strconv.Itoa(perPage)
		if page > 1 {
			url += "&page=" + strconv.Itoa(page)
		}
		resp, err := c.get(ctx, url)
		if err != nil {
			return nil, err
		}
		var list []T
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("ответ GitHub не разобран: %w", err)
		}
		out = append(out, list...)
		if !all || !strings.Contains(resp.Header.Get("Link"), `rel="next"`) {
			return out, nil
		}
	}
}

// Latest picks the newest release whose tag passes accept (by version, not
// by date). Prereleases are skipped unless pre is set.
func Latest(list []Release, pre bool, accept func(tag string) bool) (Release, bool) {
	return LatestByVersion(list, pre, accept, func(tag string) string { return tag })
}

// LatestByVersion compares product versions while preserving the source release tag.
func LatestByVersion(list []Release, pre bool, accept func(tag string) bool, version func(tag string) string) (Release, bool) {
	var best Release
	found := false
	for _, r := range list {
		if (r.Prerelease && !pre) || (accept != nil && !accept(r.Tag)) {
			continue
		}
		if _, err := Parse(version(r.Tag)); err != nil {
			continue
		}
		if !found || Compare(version(r.Tag), version(best.Tag)) > 0 {
			best, found = r, true
		}
	}
	return best, found
}

// Download saves url to path (via path+".part") and checks the SHA256
// against every non-empty want. The file is removed on mismatch. Only
// ctx limits the whole transfer; a server that stops sending for
// stallTimeout is given up.
func (c *Client) Download(ctx context.Context, url, path string, maxBytes int64, progress func(done, total int64), want ...string) (string, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := time.AfterFunc(stallTimeout, func() { cancel(errStalled) })
	defer stall.Stop()
	resp, err := c.get(ctx, url)
	if err != nil {
		return "", stalled(ctx, err)
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	part := path + ".part"
	f, err := os.Create(part)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 256<<10)
	body := io.LimitReader(resp.Body, maxBytes+1)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			stall.Reset(stallTimeout)
			// The hash is of what reached the file: a failed write
			// (disk full) is the error, not a "damaged" download.
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				os.Remove(part)
				return "", fmt.Errorf("не удалось записать файл: %w", err)
			}
			h.Write(buf[:n])
			done += int64(n)
			if done > maxBytes {
				f.Close()
				os.Remove(part)
				return "", errors.New("файл больше ожидаемого")
			}
			if progress != nil {
				progress(done, resp.ContentLength)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(part)
			return "", fmt.Errorf("загрузка оборвалась: %w", stalled(ctx, rerr))
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	checked := false
	for _, w := range want {
		if w == "" {
			continue
		}
		checked = true
		if !strings.EqualFold(w, sum) {
			os.Remove(part)
			return "", fmt.Errorf("контрольная сумма не совпала: ожидалась %s, получена %s", w, sum)
		}
	}
	if !checked {
		os.Remove(part)
		return "", errors.New("нет контрольной суммы для проверки")
	}
	os.Remove(path)
	if err := os.Rename(part, path); err != nil {
		return "", err
	}
	return sum, nil
}

// stalled names the reason when the stall timer cancelled the download.
func stalled(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), errStalled) {
		return errStalled
	}
	return err
}

// Fetch reads a small text asset (hashes.txt, SHA256SUMS).
func (c *Client) Fetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// SumFor finds name in a "sha256  name" list (sha256sum format; the name
// may carry a path like build/x.exe or a leading '*').
func SumFor(list []byte, name string) string {
	sc := bufio.NewScanner(bytes.NewReader(list))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n := strings.TrimPrefix(f[len(f)-1], "*")
		if n == name || strings.HasSuffix(n, "/"+name) {
			if len(f[0]) == 64 {
				return strings.ToLower(f[0])
			}
		}
	}
	return ""
}

// ---- versions ----

type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// Parse accepts "v1.2.3", "1.2.3", "app/v2.12.3", "v1.2.3-beta.1" and
// "v1.2.3-4-gabcdef" (git describe; treated as newer than v1.2.3).
func Parse(s string) (Version, error) {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(s, "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("не версия: %q", s)
	}
	var v Version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("не версия: %q", s)
		}
		switch i {
		case 0:
			v.Major = n
		case 1:
			v.Minor = n
		default:
			v.Patch = n
		}
	}
	v.Pre = pre
	return v, nil
}

// Compare orders versions; unparsable ones sort lowest.
func Compare(a, b string) int {
	va, ea := Parse(a)
	vb, eb := Parse(b)
	switch {
	case ea != nil && eb != nil:
		return 0
	case ea != nil:
		return -1
	case eb != nil:
		return 1
	}
	for _, d := range []int{va.Major - vb.Major, va.Minor - vb.Minor, va.Patch - vb.Patch} {
		if d != 0 {
			return d
		}
	}
	return comparePre(va.Pre, vb.Pre)
}

// comparePre: no prerelease > prerelease; git-describe suffixes ("3-gabc")
// are builds after the tag, so they rank above the plain tag. Prereleases
// compare as in semver: numeric identifiers by value (beta.10 > beta.9)
// and below alphanumeric ones, a longer list above its own prefix.
func comparePre(a, b string) int {
	desc := func(s string) bool {
		n, _, ok := strings.Cut(s, "-g")
		_, err := strconv.Atoi(n)
		return ok && err == nil
	}
	rank := func(s string) int {
		switch {
		case s == "":
			return 1
		case desc(s):
			return 2
		}
		return 0
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		return ra - rb
	}
	// "3-gabc": the commit count is a number too.
	pa := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' })
	pb := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' })
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.ParseUint(pa[i], 10, 64)
		nb, eb := strconv.ParseUint(pb[i], 10, 64)
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case ea == nil:
			return -1
		case eb == nil:
			return 1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return len(pa) - len(pb)
}
