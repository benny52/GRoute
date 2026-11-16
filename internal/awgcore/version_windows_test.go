package awgcore

import "testing"

func TestAWGReportedPackageVersion(t *testing.T) {
	for _, tc := range []struct{ output, helper, engine string }{
		{"groute-awg v1.2.3 engine=v3.1.20260828 ipc=1", "v1.2.3", "v3.1.20260828"},
		{"groute-awg v3.1.20260828 ipc=1", "v0.0.0", "v3.1.20260828"},
		{"groute-awg v1.2.3 engine=v3.1.20260828 ipc=2", "", ""},
		{"xray v1.2.3", "", ""},
	} {
		got, err := parseAWGVersion(tc.output)
		if got.helper != tc.helper || got.engine != tc.engine || (err != nil) != (tc.helper == "") {
			t.Errorf("parse %q: got %q, %v", tc.output, got, err)
		}
	}
}
