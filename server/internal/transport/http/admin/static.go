package admin

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// cspNoncePlaceholder is the literal in index.html (<meta name="csp-nonce">) replaced by the per-response nonce.
const cspNoncePlaceholder = "__CSP_NONCE__"

// StaticHandler serves the portal build: files as they are, and index.html for every other path (SPA fallback)
// with a fresh CSP style nonce per response.
type StaticHandler struct {
	files fs.FS
	// before and after are index.html split at the placeholder; both nil when the portal is not built.
	before, after []byte
}

// NewStaticHandler reads index.html once. It fails if index.html exists but does not contain the nonce placeholder
// exactly once. A build without index.html (portal not built) is accepted and answers 404.
func NewStaticHandler(files fs.FS) (*StaticHandler, error) {
	s := &StaticHandler{files: files}
	index, err := fs.ReadFile(files, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read portal index.html: %w", err)
	}
	if n := bytes.Count(index, []byte(cspNoncePlaceholder)); n != 1 {
		return nil, fmt.Errorf("portal index.html contains %s %d times, want exactly once", cspNoncePlaceholder, n)
	}
	before, after, _ := bytes.Cut(index, []byte(cspNoncePlaceholder))
	s.before, s.after = before, after
	return s, nil
}

// ServeHTTP serves existing files (assets cached immutably) and index.html for every other GET or HEAD.
func (s *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpx.WriteProblem(w, r, problem.NotFound)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if st, err := fs.Stat(s.files, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.FileServerFS(s.files).ServeHTTP(w, r)
			return
		}
	}
	s.ServeIndex(w, r)
}

// ServeIndex writes index.html with a fresh CSP nonce (16 random bytes, standard base64) in the csp-nonce meta tag
// and in the style-src directive of the response's Content-Security-Policy.
func (s *StaticHandler) ServeIndex(w http.ResponseWriter, _ *http.Request) {
	if s.before == nil {
		http.Error(w, "portal not built", http.StatusNotFound)
		return
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw) // crypto/rand.Read never returns an error
	nonce := base64.StdEncoding.EncodeToString(raw)
	body := make([]byte, 0, len(s.before)+len(nonce)+len(s.after))
	body = append(append(append(body, s.before...), nonce...), s.after...)

	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'nonce-"+nonce+"'; "+cspCommon)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(body) //nolint:gosec // G705 false positive: embedded build output plus a base64 nonce, no request data
}
