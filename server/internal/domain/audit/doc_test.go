package audit

import (
	"os"
	"testing"
)

// TestGeneratedFilesAreCurrent: the code document and the portal's code list are generated from the registry
// (`make gen`), never edited by hand (plan M4a step 0b).
func TestGeneratedFilesAreCurrent(t *testing.T) {
	for path, want := range map[string]string{
		"../../../../docs/compliance/audit-codes.md": RenderMarkdown(),
		"../../../web/src/lib/auditCodes.gen.ts":     RenderTypeScript(),
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s is not current: run make gen", path)
		}
	}
}
