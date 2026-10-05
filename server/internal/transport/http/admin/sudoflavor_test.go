package admin

import (
	"encoding/json"
	"testing"
)

func TestToSudoFlavor(t *testing.T) {
	for health, want := range map[string]string{
		`{"status":"ok","sudo_flavor":"sudo-rs"}`: "sudo-rs", `{"sudo_flavor":"classic"}`: "classic",
		`{"status":"ok"}`: "", `{"sudo_flavor":"doas"}`: "", `{}`: "", `not json`: "",
	} {
		got := toSudoFlavor(json.RawMessage(health))
		if (got == nil && want != "") || (got != nil && string(*got) != want) {
			t.Errorf("%s: %v, want %q", health, got, want)
		}
	}
}
