package store

import (
	"bytes"
	"fmt"
	"testing"
)

func TestInterruptedAssignmentsAtEachWrite(t *testing.T) {
	names := []string{"settings.json", "rulesets.json", "subscriptions.json", "profiles.json", "groups.json", "proxies.json"}
	for written := 0; written <= len(names); written++ {
		t.Run(fmt.Sprint(written), func(t *testing.T) {
			st, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			before := map[string]RawFile{}
			for i, f := range names {
				old := RawFile{}
				if i%2 == 0 {
					old = RawFile{Exists: true, Data: []byte("original")}
					if err := st.WriteRaw(f, old); err != nil {
						t.Fatal(err)
					}
				}
				before[f] = old
			}
			if err := st.BeginAssignments(before); err != nil {
				t.Fatal(err)
			}
			for _, f := range names[:written] {
				if err := st.WriteRaw(f, RawFile{Exists: true, Data: []byte("replacement")}); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := Open(st.Dir)
			if err != nil {
				t.Fatal(err)
			}
			for f, expected := range before {
				got, err := reopened.ReadRaw(f)
				if err != nil || got.Exists != expected.Exists || !bytes.Equal(got.Data, expected.Data) {
					t.Fatal(f, err)
				}
			}
			if _, err = Open(st.Dir); err != nil {
				t.Fatal("recovery not repeatable", err)
			}
		})
	}
}
