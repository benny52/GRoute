package zapret

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// WhiteNames are sites on TSPU's white list: a fake or an overlap that
// names one of them can keep a connection out of the "16-20 KB" cut of
// hosting and CDN addresses (Flowseal uses 4pda.to's ClientHello, zapret2
// ships vk.com's). The generator tries which works on a network.
var WhiteNames = []string{"vk.com", "ya.ru", "gosuslugi.ru", "max.ru", "4pda.to", "ozon.ru"}

// whiteKey is the fake's key: vk.com's comes with zapret2, the others
// HyRoute makes.
func whiteKey(name string) string {
	if name == "vk.com" {
		return "vk"
	}
	return "w_" + strings.NewReplacer(".", "_", "-", "_").Replace(name)
}

// whiteByKey: the white-listed name of a HyRoute-made fake's key.
func whiteByKey(k string) (string, bool) {
	if !strings.HasPrefix(k, "w_") {
		return "", false
	}
	for _, w := range WhiteNames {
		if whiteKey(w) == k {
			return w, true
		}
	}
	return "", false
}

// whiteBlob is the blob name winws2 knows a made fake by.
func whiteBlob(k string) string { return k }

// fakeFile is the file of a made fake in the lists folder.
func fakeFile(k string) string { return "fake_" + k + ".bin" }

// WriteFakes makes the ClientHellos of the white-listed names into dir
// (once: a file that is there and looks like one stays). They are like
// Chrome's without the post-quantum key share, so each fits one packet, as
// a fake must.
func WriteFakes(dir string) error {
	for _, w := range WhiteNames {
		k := whiteKey(w)
		if _, ok := whiteByKey(k); !ok {
			continue // zapret2's
		}
		path := filepath.Join(dir, fakeFile(k))
		if b, err := os.ReadFile(path); err == nil && looksLikeHello(b, w) {
			continue
		}
		b, err := ClientHello(w)
		if err != nil {
			return fmt.Errorf("фейк %s: %w", w, err)
		}
		if err := writeIfChanged(path, b); err != nil {
			return err
		}
	}
	return nil
}

// ClientHello is a TLS record with a Chrome-like ClientHello naming host.
func ClientHello(host string) ([]byte, error) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	u := utls.UClient(a, &utls.Config{ServerName: host}, utls.HelloChrome_120)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	raw := u.HandshakeState.Hello.Raw
	if len(raw) == 0 || len(raw) > 1200 {
		return nil, fmt.Errorf("ClientHello %d байт", len(raw))
	}
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	return rec, nil
}

func looksLikeHello(b []byte, host string) bool {
	return len(b) > 5 && b[0] == 0x16 && bytes.Contains(b, []byte(host))
}

// fakeArgs are the --blob options of the made fakes the plans use.
func fakeArgs(lists string, plans map[Target]Plan) []string {
	var keys []string
	for _, p := range plans {
		for _, id := range p.Methods {
			if s, ok := ParseStrategy(id); ok {
				for _, k := range s.whiteBlobs() {
					if !slices.Contains(keys, k) {
						keys = append(keys, k)
					}
				}
			}
		}
	}
	slices.Sort(keys)
	var out []string
	for _, k := range keys {
		out = append(out, "--blob="+whiteBlob(k)+":@"+filepath.Join(lists, fakeFile(k)))
	}
	return out
}
