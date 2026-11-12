package app

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSubscriptionDetailsSnapshot(t *testing.T) {
	c, _ := newCtl(t)
	cfg := []byte(`{"containers":[{"container":"amnezia-awg","awg":{"privateKey":"private-marker"}}]}`)
	var packed bytes.Buffer
	binary.Write(&packed, binary.BigEndian, uint32(len(cfg)))
	w := zlib.NewWriter(&packed)
	w.Write(cfg)
	w.Close()
	var lines []string
	for i := 1; i <= 6; i++ {
		lines = append(lines, fmt.Sprintf("hy2://test-password@node%d.invalid:443#Node%d", i, i))
	}
	lines = append(lines, vlessLink, "vpn://"+base64.RawURLEncoding.EncodeToString(packed.Bytes()))
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
	sub := addSub(t, c, &body)
	verify := func(c *Controller) {
		t.Helper()
		d, err := c.SubscriptionDetails(sub.ID)
		if err != nil || len(d.Profiles) != 7 || d.Profiles[6].Protocol != "VLESS" || d.Profiles[0].Name != "Node1" || d.Profiles[0].Protocol != "Hysteria 2" ||
			len(d.Skipped) != 1 || d.Skipped[0].Protocol != "AmneziaWG" || d.Skipped[0].Reason == "" || d.Partial {
			t.Fatalf("unexpected import report: %+v, %v", d, err)
		}
		report, _ := json.Marshal(d)
		for _, secret := range []string{"test-password", "private-marker", "://", base64.RawURLEncoding.EncodeToString(packed.Bytes())} {
			if bytes.Contains(report, []byte(secret)) {
				t.Fatal("import report leaked source data")
			}
		}
	}
	verify(c)
	body = strings.Join([]string{lines[0], lines[0] + "-copy", "vpn://opaque-secret#Unknown", "other://secret@private.invalid#Other", "hy2://pw@domain.invalid:bad-secret#Malformed"}, "\n")
	if _, err := c.UpdateSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	d, err := c.SubscriptionDetails(sub.ID)
	if err != nil || len(d.Profiles) != 1 || len(d.Duplicates) != 1 || len(d.Skipped) != 3 || d.Skipped[0].Protocol == "AmneziaWG" {
		t.Fatalf("updated report: %+v, %v", d, err)
	}
	report, _ := json.Marshal(d)
	if bytes.Contains(report, []byte("secret")) {
		t.Fatal("raw input in a skip reason")
	}
	if _, err := c.RollbackSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := newCtlAt(t, c.Store)
	verify(reloaded)
	c.Store.DeleteSnapshots(sub.ID)
	d, err = c.SubscriptionDetails(sub.ID)
	if err != nil || !d.Partial || len(d.Profiles) != 7 || len(d.Skipped) != 1 {
		t.Fatal("missing legacy snapshot lost saved summary")
	}
}
