// Command testlive turns the `go test -json` stream of a long run into the live `go test -v` log (PDK-962, plan M19
// D4): every output line appears the moment the test writes it, lines of subtests carry the test name, and the run
// fails when no test started, as test/require-tests.sh does for `go test -v`. go test's own exit code reaches the
// caller through `set -o pipefail`.
//
//	go test -json ./... | testlive [-raw file]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type event struct {
	Action string
	Test   string
	Output string
}

func main() {
	raw := flag.String("raw", "", "also write the unchanged JSON stream to this file")
	flag.Parse()
	os.Exit(runMain(*raw))
}

func runMain(raw string) int {
	tee := io.Discard
	if raw != "" {
		f, err := os.Create(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "testlive:", err)
			return 2
		}
		defer f.Close()
		tee = f
	}
	return run(os.Stdin, os.Stdout, os.Stderr, tee)
}

func run(in io.Reader, out, errw, tee io.Writer) int {
	ran := 0
	r := bufio.NewReader(in)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			_, _ = io.WriteString(tee, line)
			var ev event
			if json.Unmarshal([]byte(line), &ev) != nil {
				// go test prints build errors outside the JSON stream.
				_, _ = io.WriteString(out, line)
			} else {
				switch ev.Action {
				case "run":
					ran++
				case "output":
					_, _ = io.WriteString(out, format(ev))
				}
			}
		}
		if err != nil {
			break
		}
	}
	if ran == 0 {
		fmt.Fprintln(errw, "no test ran: the -run filter (T or SUITE) matched nothing; a gate run without tests is not green")
		return 1
	}
	return 0
}

// format prefixes every line of a subtest's output with the subtest's name, so lines of parallel subtests stay
// attributable; go test's own === and --- lines already name their test.
func format(ev event) string {
	if !strings.Contains(ev.Test, "/") {
		return ev.Output
	}
	var b strings.Builder
	for _, l := range strings.SplitAfter(ev.Output, "\n") {
		t := strings.TrimLeft(l, " ")
		if l == "" || strings.HasPrefix(t, "=== ") || strings.HasPrefix(t, "--- ") {
			b.WriteString(l)
			continue
		}
		b.WriteString("[" + ev.Test + "] " + strings.TrimLeft(l, " "))
	}
	return b.String()
}
