package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const goTestList = `TestB
TestA
ExampleC
ok  	github.com/phischl/paddock-mdm/test/acceptance	0.009s
?   	github.com/phischl/paddock-mdm/test/acceptance/portal	[no test files]
TestA
TestD
TestE
TestF
ok  	github.com/phischl/paddock-mdm/test/acceptance/internal/authflow	0.002s
`

const weightsFile = `# seconds test [group]
300 TestA
100 TestB
90 TestD parallel
80 TestE parallel

50 TestGone
`

func shardOutput(t *testing.T, shard string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weights.txt")
	if err := os.WriteFile(path, []byte(weightsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"-shard", shard, "-weights", path, "-default", "60"}, strings.NewReader(goTestList), &out)
	return strings.TrimSpace(out.String()), err
}

func TestEveryTestRunsInExactlyOneShard(t *testing.T) {
	all := []string{"ExampleC", "TestA", "TestB", "TestD", "TestE", "TestF"}
	for total := 1; total <= 4; total++ {
		seen := map[string]int{}
		for i := 1; i <= total; i++ {
			re, err := shardOutput(t, strconv.Itoa(i)+"/"+strconv.Itoa(total))
			if err != nil {
				t.Fatalf("shard %d/%d: %v", i, total, err)
			}
			rx := regexp.MustCompile(re)
			for _, n := range all {
				if rx.MatchString(n) {
					seen[n]++
				}
			}
			if rx.MatchString("TestGone") || rx.MatchString("TestAX") {
				t.Errorf("shard %d/%d regex %q selects a test that is not listed", i, total, re)
			}
		}
		for _, n := range all {
			if seen[n] != 1 {
				t.Errorf("%d shards: %s selected %d times, want exactly once", total, n, seen[n])
			}
		}
	}
}

func TestUnknownTestRunsInExactlyOneShard(t *testing.T) {
	w, err := parseWeights(strings.NewReader(weightsFile))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"TestA", "TestB", "TestBrandNew", "TestD", "TestE"}
	for total := 1; total <= 4; total++ {
		shards := assign(names, w, 60, total)
		var union []string
		for _, s := range shards {
			union = append(union, s...)
		}
		slices.Sort(union)
		if !slices.Equal(union, names) {
			t.Errorf("%d shards: union %v, want %v without duplicates", total, union, names)
		}
		if err := verify(names, shards); err != nil {
			t.Errorf("%d shards: verify: %v", total, err)
		}
	}
}

func TestVerifyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weights.txt")
	if err := os.WriteFile(path, []byte(weightsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-verify", "3", "-weights", path}, strings.NewReader(goTestList+"TestBrandNew\n"), &out); err != nil {
		t.Fatalf("verify 3: %v", err)
	}
	if !strings.Contains(out.String(), "7 tests, 3 shards") {
		t.Errorf("verify output %q", out.String())
	}
	for _, args := range [][]string{{"-verify", "7"}, {"-verify", "1", "-shard", "1/1"}, {"-verify", "-1"}} {
		if err := run(args, strings.NewReader(goTestList), &out); err == nil {
			t.Errorf("run %v succeeded, want error", args)
		}
	}
}

func TestVerifyRejectsBrokenShards(t *testing.T) {
	names := []string{"TestA", "TestAB", "TestB"}
	cases := map[string][][]string{
		"missing test":  {{"TestA"}, {"TestB"}},
		"duplicate":     {{"TestA", "TestB"}, {"TestB", "TestAB"}},
		"empty shard":   {{"TestA", "TestAB", "TestB"}, {}},
		"unknown entry": {{"TestA", "TestAB"}, {"TestC"}},
	}
	for name, shards := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verify(names, shards); err == nil {
				t.Errorf("verify(%v) succeeded, want error", shards)
			}
		})
	}
	if err := verify(names, [][]string{{"TestA"}, {"TestAB", "TestB"}}); err != nil {
		t.Errorf("verify of a correct split: %v", err)
	}
}

func TestAssignBalancesAndKeepsGroupsTogether(t *testing.T) {
	w, err := parseWeights(strings.NewReader(weightsFile))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"ExampleC", "TestA", "TestB", "TestD", "TestE", "TestF"}
	got := assign(names, w, 60, 2)
	want := [][]string{{"TestA"}, {"ExampleC", "TestB", "TestD", "TestE", "TestF"}}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("assign = %v, want %v", got, want)
	}

	got3 := assign(names, w, 60, 3)
	for _, s := range got3 {
		if slices.Contains(s, "TestD") != slices.Contains(s, "TestE") {
			t.Errorf("group parallel split across shards: %v", got3)
		}
	}
}

func TestAssignIsDeterministic(t *testing.T) {
	w, err := parseWeights(strings.NewReader(weightsFile))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"ExampleC", "TestA", "TestB", "TestD", "TestE", "TestF"}
	first := assign(names, w, 60, 3)
	for range 20 {
		if got := assign(names, w, 60, 3); !slices.EqualFunc(got, first, slices.Equal) {
			t.Fatalf("assign not deterministic: %v vs %v", got, first)
		}
	}
}

func TestRunRejectsInvalidInput(t *testing.T) {
	cases := map[string]struct {
		args  []string
		stdin string
	}{
		"missing shard":   {args: nil, stdin: goTestList},
		"shard zero":      {args: []string{"-shard", "0/3"}, stdin: goTestList},
		"shard above n":   {args: []string{"-shard", "4/3"}, stdin: goTestList},
		"not a fraction":  {args: []string{"-shard", "2"}, stdin: goTestList},
		"empty test list": {args: []string{"-shard", "1/1"}, stdin: "ok  \tpkg\t0.1s\n"},
		"empty shard":     {args: []string{"-shard", "3/3"}, stdin: "TestA\nTestB\n"},
		"missing weights": {args: []string{"-shard", "1/1", "-weights", "/nonexistent/weights.txt"}, stdin: goTestList},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run(tc.args, strings.NewReader(tc.stdin), &out); err == nil {
				t.Errorf("run succeeded with output %q, want error", out.String())
			}
		})
	}
}

func TestParseWeightsRejectsMalformedLines(t *testing.T) {
	for _, line := range []string{"TestA", "x TestA", "-1 TestA", "1 TestA g extra"} {
		if _, err := parseWeights(strings.NewReader(line)); err == nil {
			t.Errorf("parseWeights(%q) succeeded, want error", line)
		}
	}
}

func TestUnparsableTestNameFailsInsteadOfDropping(t *testing.T) {
	for _, name := range []string{"TestÄnderung", "TestA-B", "Example_x.y", "FuzzA B"} {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]string{{"-verify", "2"}, {"-shard", "1/2"}} {
				var out bytes.Buffer
				err := run(args, strings.NewReader(goTestList+name+"\n"), &out)
				if err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("run %v with listed test %q: err %v, want an error naming the test", args, name, err)
				}
			}
		})
	}
}
