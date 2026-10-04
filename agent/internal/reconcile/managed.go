package reconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/paddock-mdm/paddock/agent/internal/fsutil"
)

// Managed is managed.json: every file Paddock wrote, with the hex SHA-256 of the content it wrote (plan M2b
// decision 10). Only files listed here are ever deleted, and only while unchanged.
type Managed struct {
	path  string
	Files map[string]string `json:"files"`
}

// LoadManaged reads managed.json; a missing file is an empty record.
func LoadManaged(path string) (*Managed, error) {
	m := &Managed{path: path, Files: map[string]string{}}
	data, err := os.ReadFile(path) //nolint:gosec // path of the agent layout
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed files: %w", err)
	}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.Files == nil {
		m.Files = map[string]string{}
	}
	return m, nil
}

// Record stores that Paddock wrote path with content hash sum.
func (m *Managed) Record(path, sum string) error {
	if m.Files[path] == sum {
		return nil
	}
	m.Files[path] = sum
	return m.save()
}

// Forget removes path from the record.
func (m *Managed) Forget(path string) error {
	if _, ok := m.Files[path]; !ok {
		return nil
	}
	delete(m.Files, path)
	return m.save()
}

// Paths returns the recorded paths, sorted.
func (m *Managed) Paths() []string {
	out := make([]string, 0, len(m.Files))
	for p := range m.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (m *Managed) save() error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(m.path, append(data, '\n'), 0o600, 0o700)
}
