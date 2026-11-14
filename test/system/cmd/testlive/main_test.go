package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCode int
		want     string
		wantErr  string
	}{
		{"passes through output", `{"Action":"run","Test":"TestA"}
{"Action":"output","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Action":"output","Test":"TestA","Output":"    a_test.go:1: hello\n"}
{"Action":"output","Test":"TestA","Output":"--- PASS: TestA (0.00s)\n"}
`, 0, "=== RUN   TestA\n    a_test.go:1: hello\n--- PASS: TestA (0.00s)\n", ""},
		{"prefixes subtests", `{"Action":"run","Test":"TestA/vm1"}
{"Action":"output","Test":"TestA/vm1","Output":"=== RUN   TestA/vm1\n"}
{"Action":"output","Test":"TestA/vm1","Output":"    a_test.go:1: waiting\n"}
{"Action":"output","Test":"TestA/vm1","Output":"    --- PASS: TestA/vm1 (0.00s)\n"}
`, 0, "=== RUN   TestA/vm1\n[TestA/vm1] a_test.go:1: waiting\n    --- PASS: TestA/vm1 (0.00s)\n", ""},
		{"no test ran", `{"Action":"output","Output":"testing: warning: no tests to run\n"}
`, 1, "testing: warning: no tests to run\n", "no test ran"},
		{"empty stream", "", 1, "", "no test ran"},
		{"non-JSON line is kept", "# build failed\n", 1, "# build failed\n", "no test ran"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errw, raw bytes.Buffer
			code := run(strings.NewReader(c.in), &out, &errw, &raw)
			if code != c.wantCode || out.String() != c.want || !strings.Contains(errw.String(), c.wantErr) {
				t.Errorf("code %d out %q err %q; want %d %q %q", code, out.String(), errw.String(), c.wantCode, c.want, c.wantErr)
			}
			if raw.String() != c.in {
				t.Errorf("raw stream %q, want the input unchanged", raw.String())
			}
		})
	}
}
