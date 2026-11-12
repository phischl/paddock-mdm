package admin

import (
	"bytes"
	"errors"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// TestReadPackageUpload: the upload form carries one file and the optional package, version and architecture; a
// repeated or unknown field and an overlong text field are refused before the use case.
func TestReadPackageUpload(t *testing.T) {
	form := func(fields ...[2]string) *multipart.Reader {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for _, f := range fields {
			if f[0] == "file" {
				part, _ := w.CreateFormFile("file", "x.deb")
				_, _ = part.Write([]byte(f[1]))
				continue
			}
			_ = w.WriteField(f[0], f[1])
		}
		_ = w.Close()
		return multipart.NewReader(&b, w.Boundary())
	}
	in, err := readPackageUpload(form([2]string{"file", "!<arch>\n"}, [2]string{"package", "acme"}, [2]string{"version", "1.0"},
		[2]string{"architecture", "amd64"}))
	if err != nil || string(in.File) != "!<arch>\n" || in.Package != "acme" || in.Version != "1.0" || in.Architecture != "amd64" {
		t.Fatalf("read %+v, %v", in, err)
	}
	for name, r := range map[string]*multipart.Reader{
		"twice":    form([2]string{"file", "a"}, [2]string{"file", "b"}),
		"unknown":  form([2]string{"file", "a"}, [2]string{"note", "b"}),
		"too long": form([2]string{"file", "a"}, [2]string{"version", strings.Repeat("1", maxUploadField+1)}),
		"no body":  nil,
	} {
		if _, err := readPackageUpload(r); !errors.Is(err, problem.InvalidRequest) {
			t.Errorf("%s: %v, want invalid_request", name, err)
		}
	}
}
