package authentik

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// devBlueprintDir is the directory of the development blueprint, mounted by compose.dev.yaml only.
func devBlueprintDir() string {
	return filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "dev")
}

// TestBlueprintsDoNotNestOtherBlueprints (plan M12h-2 amendment g): no Paddock blueprint applies another one with
// metaapplyblueprint. Authentik applies every file at startup, concurrently, and a nested apply upserts the same objects
// in two threads at once, which deadlocked its workers until the providers never appeared (CI run 43731878343).
func TestBlueprintsDoNotNestOtherBlueprints(t *testing.T) {
	var files []string
	for _, dir := range []string{productionBlueprintDir(), devBlueprintDir()} {
		found, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, found...)
	}
	if len(files) < 6 {
		t.Fatalf("found %d blueprints, want the five production blueprints and the development one", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // paths below the repository's blueprint directories
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "metaapplyblueprint") {
			t.Errorf("%s applies another blueprint (metaapplyblueprint); authentik-apply-blueprints.sh orders the files instead", f)
		}
	}
}

// TestApplyScriptListsEveryBlueprint (plan M12h-2 amendment g): authentik-apply-blueprints.sh applies every production
// blueprint, the portal first, because the others find its objects with !Find; a new file that is not listed would
// depend on Authentik's unordered startup apply alone.
func TestApplyScriptListsEveryBlueprint(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "compose", "scripts", "authentik-apply-blueprints.sh"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)\nblueprints=\((.*?)\n\)`).FindSubmatch(script)
	if block == nil {
		t.Fatal("authentik-apply-blueprints.sh has no blueprints=( … ) list")
	}
	var listed []string
	for _, m := range regexp.MustCompile(`paddock/(\S+\.yaml)`).FindAllSubmatch(block[1], -1) {
		listed = append(listed, string(m[1]))
	}
	found, err := filepath.Glob(filepath.Join(productionBlueprintDir(), "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range found {
		files = append(files, filepath.Base(f))
	}
	if len(listed) == 0 || listed[0] != "paddock-portal.yaml" {
		t.Errorf("the script applies %v, want paddock-portal.yaml first", listed)
	}
	sortedListed := slices.Sorted(slices.Values(listed))
	if !slices.Equal(sortedListed, files) {
		t.Errorf("the script applies %v, the blueprint directory holds %v", sortedListed, files)
	}
	if !strings.Contains(string(script), "dev_blueprint=paddock-dev/paddock-dev.yaml") {
		t.Error("the script does not apply the development blueprint paddock-dev/paddock-dev.yaml")
	}
}

// TestApplyScriptChecksDefinedObjects (decisions-alpha11 §69): every provider, application and flow that
// authentik-apply-blueprints.sh requires after its applies is defined by name or slug in a production blueprint, so a
// rename cannot make every start fail.
func TestApplyScriptChecksDefinedObjects(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "compose", "scripts", "authentik-apply-blueprints.sh"))
	if err != nil {
		t.Fatal(err)
	}
	found, err := filepath.Glob(filepath.Join(productionBlueprintDir(), "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, f := range found {
		raw, err := os.ReadFile(f) //nolint:gosec // paths below the repository's blueprint directory
		if err != nil {
			t.Fatal(err)
		}
		all.Write(raw)
	}
	keys := map[string]string{"providers": "name", "applications": "slug", "flows": "slug"}
	for list, key := range keys {
		block := regexp.MustCompile(`(?s)\n` + list + `=\((.*?)\)`).FindSubmatch(script)
		if block == nil {
			t.Fatalf("authentik-apply-blueprints.sh has no %s=( … ) list", list)
		}
		names := strings.Fields(string(block[1]))
		if len(names) == 0 {
			t.Errorf("the %s list is empty", list)
		}
		for _, n := range names {
			if !regexp.MustCompile(`(?m)^\s+` + key + `: ` + regexp.QuoteMeta(n) + `\s*$`).MatchString(all.String()) {
				t.Errorf("%s lists %s, which no production blueprint defines with %s: %s", list, n, key, n)
			}
		}
	}
}
