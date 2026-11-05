package siemcontent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/oasdiff/yaml"
	"github.com/stretchr/testify/require"

	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
)

const sigmaGlob = "../../../integrations/sigma/paddock_*.yml"

// sigmaLevels maps a Wazuh rule level to the Sigma level of the same detection.
var sigmaLevels = map[int]string{12: "critical", 10: "high", 7: "medium", 5: "low"}

type sigmaRule struct {
	Title       string   `json:"title"`
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Logsource   struct {
		Product string `json:"product"`
		Service string `json:"service"`
	} `json:"logsource"`
	Detection map[string]any `json:"detection"`
	Level     string         `json:"level"`
}

func loadSigma(t *testing.T) map[string]sigmaRule {
	t.Helper()
	files, err := filepath.Glob(sigmaGlob)
	require.NoError(t, err)
	require.NotEmpty(t, files, "no Sigma rule found")
	out := map[string]sigmaRule{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		j, err := yaml.YAMLToJSON(raw)
		require.NoError(t, err, f)
		var r sigmaRule
		// Unknown top-level keys are legal Sigma; only the keys this test reads are decoded.
		require.NoError(t, json.Unmarshal(j, &r), f)
		out[filepath.Base(f)] = r
	}
	return out
}

// eventFields are the dotted JSON names of audit.Event, such as code and actor.type.
func eventFields() map[string]bool {
	out := map[string]bool{}
	var walk func(prefix string, t reflect.Type)
	walk = func(prefix string, t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			ft := t.Field(i).Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() == t.PkgPath() {
				walk(prefix+tag+".", ft)
				continue
			}
			out[prefix+tag] = true
		}
	}
	walk("", reflect.TypeOf(audit.Event{}))
	return out
}

func registryParams() map[string]bool {
	out := map[string]bool{}
	for _, d := range audit.Definitions() {
		for _, p := range d.Params {
			out[p] = true
		}
	}
	return out
}

func asStrings(t *testing.T, v any) []string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			s, ok := e.(string)
			require.True(t, ok, "list entries are strings")
			out = append(out, s)
		}
		return out
	}
	require.Failf(t, "unsupported value", "%v", v)
	return nil
}

func TestSigmaRules(t *testing.T) {
	rules := loadRules(t)
	byID := map[string]rule{}
	for _, r := range rules {
		byID[strconv.Itoa(r.ID)] = r
	}
	fields := eventFields()
	require.True(t, fields["code"] && fields["actor.type"] && fields["outcome"], "event field walk")
	params := registryParams()
	covered := map[string]string{}
	seenIDs := map[string]bool{}

	for file, s := range loadSigma(t) {
		require.NotEmpty(t, s.Title, file)
		require.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, s.ID, file)
		require.False(t, seenIDs[s.ID], "%s: duplicate id", file)
		seenIDs[s.ID] = true
		require.NotEmpty(t, s.Description, file)
		require.Equal(t, "paddock", s.Logsource.Product, file)
		require.Equal(t, "audit", s.Logsource.Service, file)

		var wazuhID string
		for _, tag := range s.Tags {
			if id, ok := strings.CutPrefix(tag, "paddock.wazuh_"); ok {
				wazuhID = id
			}
		}
		r, ok := byID[wazuhID]
		require.True(t, ok, "%s: tag paddock.wazuh_<id> must name a rule of the Wazuh file", file)
		require.Zero(t, r.Frequency, "%s: frequency rules have no Sigma twin", file)
		require.Empty(t, covered[wazuhID], "%s: rule %s already has %s", file, wazuhID, covered[wazuhID])
		covered[wazuhID] = file
		require.Equal(t, sigmaLevels[r.Level], s.Level, "%s: level of Wazuh rule %s", file, wazuhID)

		cond, _ := s.Detection["condition"].(string)
		require.NotEmpty(t, cond, file)
		for name, sel := range s.Detection {
			if name == "condition" {
				continue
			}
			require.Contains(t, cond, name, "%s: selection %s unused", file, name)
			items, ok := sel.(map[string]any)
			require.True(t, ok, "%s: selection %s is a map of fields", file, name)
			for key, val := range items {
				field, mod, _ := strings.Cut(key, "|")
				if p, ok := strings.CutPrefix(field, "params."); ok {
					require.True(t, params[p], "%s: %s is no param of any registered code", file, field)
				} else {
					require.True(t, fields[field], "%s: %s is no field of paddock.audit.v1", file, field)
				}
				require.Contains(t, []string{"", "startswith", "contains"}, mod, "%s: modifier %s", file, mod)
				if field != "code" {
					continue
				}
				for _, v := range asStrings(t, val) {
					var hit bool
					for _, c := range emitted() {
						switch mod {
						case "startswith":
							hit = hit || strings.HasPrefix(string(c), v)
						case "contains":
							hit = hit || strings.Contains(string(c), v)
						default:
							hit = hit || string(c) == v
						}
					}
					require.True(t, hit, "%s: code value %q matches no registered code", file, v)
				}
			}
		}
	}
	for id, r := range byID {
		if r.Frequency > 0 || r.DecodedAs != "" || id == "100903" {
			continue
		}
		require.NotEmpty(t, covered[id], "Wazuh rule %s has no Sigma rule", id)
	}
}
