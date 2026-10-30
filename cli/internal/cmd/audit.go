package cmd

import (
	"errors"
	"os"

	"github.com/phischl/paddock-mdm/cli/internal/evidence"
)

// runAuditVerifyExport reads no configuration and no token and opens no connection: the auditor has nothing but the
// package and the fingerprint obtained out of band.
func runAuditVerifyExport(e Env, args []string) error {
	var fingerprint, output string
	fs := newFlags("audit verify-export")
	fs.StringVar(&fingerprint, "fingerprint", "", "")
	fs.StringVar(&output, "o", "text", "")
	fs.StringVar(&output, "output", "text", "")
	// The file may come before or after the flags; flag.Parse stops at the first operand.
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			return usagef("%v", err)
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 1 {
		return usagef("usage: paddockctl audit verify-export <file> [--fingerprint <hex>] [-o text|json]")
	}
	g := globals{output: output}
	if err := g.requireOutput("text", "json"); err != nil {
		return err
	}
	f, err := os.Open(files[0])
	if err != nil {
		return usagef("cannot read %s: %v", files[0], err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return usagef("cannot read %s: %v", files[0], err)
	}
	res, err := evidence.Verify(f, info.Size(), evidence.Options{Fingerprint: fingerprint})
	switch {
	case errors.Is(err, evidence.ErrNotTar), errors.Is(err, evidence.ErrLimit):
		return usagef("%s: %v", files[0], err)
	case err != nil:
		return err
	}
	if output == "json" {
		if err := writeJSON(e.Stdout, res); err != nil {
			return err
		}
	} else {
		res.WriteText(e.Stdout)
	}
	if !res.OK {
		return verifyFailedError{}
	}
	return nil
}
