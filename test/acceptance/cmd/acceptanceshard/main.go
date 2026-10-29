// Command acceptanceshard splits the acceptance gates into shards that CI runs as parallel jobs, each against its own
// stack (`make acceptance SHARD=i/n`, PDK-359). It reads the output of `go test -list` on stdin and prints the -run
// regex of shard i. Every listed test lands in exactly one shard: the assignment is a deterministic greedy balance
// over the measured durations of the weights file, so tests that are missing from it still run, with a default
// weight. Tests that share a group in the weights file (gates that run together with t.Parallel) stay in one shard.
// With -verify n it checks instead that the n shard regexes select every listed test exactly once (CI runs this
// before each shard).
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "acceptanceshard:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("acceptanceshard", flag.ContinueOnError)
	shardFlag := fs.String("shard", "", "shard to print, as i/n (1-based)")
	weightsPath := fs.String("weights", "", "file with lines '<seconds> <test> [group]'")
	defaultWeight := fs.Int("default", 60, "weight in seconds of tests missing from the weights file")
	verifyTotal := fs.Int("verify", 0, "instead of printing a shard, check that n shards select every listed test exactly once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var index, total int
	if *verifyTotal == 0 {
		var err error
		if index, total, err = parseShard(*shardFlag); err != nil {
			return err
		}
	} else if *verifyTotal < 1 || *shardFlag != "" {
		return errors.New("-verify wants n >= 1 and no -shard")
	}
	names, err := parseList(stdin)
	if err != nil {
		return err
	}
	var w weights
	if *weightsPath != "" {
		f, err := os.Open(*weightsPath)
		if err != nil {
			return fmt.Errorf("open weights: %w", err)
		}
		w, err = parseWeights(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("weights %s: %w", *weightsPath, err)
		}
	}
	if *verifyTotal > 0 {
		if err := verify(names, assign(names, w, *defaultWeight, *verifyTotal)); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%d tests, %d shards: every test selected by exactly one shard\n", len(names), *verifyTotal)
		return err
	}
	shards := assign(names, w, *defaultWeight, total)
	shard := shards[index-1]
	if len(shard) == 0 {
		return fmt.Errorf("shard %d/%d has no tests; use fewer shards", index, total)
	}
	_, err = fmt.Fprintln(stdout, runRegex(shard))
	return err
}

func parseShard(s string) (index, total int, err error) {
	i, n, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, fmt.Errorf("shard %q: want i/n", s)
	}
	index, err1 := strconv.Atoi(i)
	total, err2 := strconv.Atoi(n)
	if err1 != nil || err2 != nil || total < 1 || index < 1 || index > total {
		return 0, 0, fmt.Errorf("shard %q: want i/n with 1 <= i <= n", s)
	}
	return index, total, nil
}

// isTestLine reports whether a `go test -list` line lists a test, fuzz target or example, the entries -run selects.
func isTestLine(line string) bool {
	return strings.HasPrefix(line, "Test") || strings.HasPrefix(line, "Fuzz") || strings.HasPrefix(line, "Example")
}

// isTestName reports whether a listed test name consists only of the characters runRegex and the shard regexes are
// known to handle.
func isTestName(line string) bool {
	return !strings.ContainsFunc(line, func(r rune) bool {
		return r != '_' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
	})
}

// parseList returns the sorted, unique test names of `go test -list` output; package summary lines are skipped.
// A name that occurs in several packages is one entry, and -run then selects it in each of them. A listed test whose
// name it cannot parse is an error: dropping it would leave the test out of every shard.
func parseList(r io.Reader) ([]string, error) {
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !isTestLine(line) {
			continue
		}
		if !isTestName(line) {
			return nil, fmt.Errorf("test list: cannot parse test name %q", line)
		}
		seen[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read test list: %w", err)
	}
	if len(seen) == 0 {
		return nil, errors.New("test list is empty")
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

type weights struct {
	seconds map[string]int
	group   map[string]string
}

func parseWeights(r io.Reader) (weights, error) {
	w := weights{seconds: map[string]int{}, group: map[string]string{}}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 || len(fields) > 3 {
			return weights{}, fmt.Errorf("line %d: want '<seconds> <test> [group]'", line)
		}
		sec, err := strconv.Atoi(fields[0])
		if err != nil || sec < 0 {
			return weights{}, fmt.Errorf("line %d: invalid seconds %q", line, fields[0])
		}
		w.seconds[fields[1]] = sec
		if len(fields) == 3 {
			w.group[fields[1]] = fields[2]
		}
	}
	if err := sc.Err(); err != nil {
		return weights{}, fmt.Errorf("read weights: %w", err)
	}
	return w, nil
}

type unit struct {
	names  []string
	weight int
}

// assign distributes names over total shards: units (a group or a single test) in descending weight, each to the
// shard with the least load so far, ties to the lower shard. A group weighs as much as its slowest member because
// its tests run in parallel.
func assign(names []string, w weights, defaultWeight, total int) [][]string {
	byKey := map[string]*unit{}
	var units []*unit
	for _, n := range names {
		sec, ok := w.seconds[n]
		if !ok {
			sec = defaultWeight
		}
		key := "test:" + n
		if g, ok := w.group[n]; ok {
			key = "group:" + g
		}
		u, ok := byKey[key]
		if !ok {
			u = &unit{}
			byKey[key] = u
			units = append(units, u)
		}
		u.names = append(u.names, n)
		u.weight = max(u.weight, sec)
	}
	slices.SortStableFunc(units, func(a, b *unit) int { return b.weight - a.weight })

	shards := make([][]string, total)
	load := make([]int, total)
	for _, u := range units {
		target := 0
		for i := 1; i < total; i++ {
			if load[i] < load[target] {
				target = i
			}
		}
		shards[target] = append(shards[target], u.names...)
		load[target] += u.weight
	}
	for _, s := range shards {
		slices.Sort(s)
	}
	return shards
}

// verify checks the -run regexes that the shards produce against the full test list: every listed test is selected
// by exactly one shard and no shard is empty. It checks the regexes rather than the slices so that a quoting or
// anchoring mistake in runRegex cannot hide a test.
func verify(names []string, shards [][]string) error {
	count := make(map[string]int, len(names))
	for i, shard := range shards {
		if len(shard) == 0 {
			return fmt.Errorf("shard %d/%d has no tests; use fewer shards", i+1, len(shards))
		}
		re, err := regexp.Compile(runRegex(shard))
		if err != nil {
			return fmt.Errorf("shard %d/%d: %w", i+1, len(shards), err)
		}
		for _, n := range names {
			if re.MatchString(n) {
				count[n]++
			}
		}
	}
	var problems []string
	for _, n := range names {
		if count[n] != 1 {
			problems = append(problems, fmt.Sprintf("%s selected by %d shards", n, count[n]))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("shards are not exhaustive and disjoint: %s", strings.Join(problems, "; "))
	}
	return nil
}

func runRegex(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = regexp.QuoteMeta(n)
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}
