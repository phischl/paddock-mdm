package main

import (
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/config"
)

// TestNotifierSettings: defaults, limits, and PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE only in development (plan M9
// decision 20).
func TestNotifierSettings(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		env := map[string]string{"PADDOCK_PUBLIC_ADMIN_URL": "https://admin.example/"}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}
	load := func(env map[string]string) (notifierSettings, error) {
		l := config.NewLoaderFrom(env)
		common := config.LoadCommon(l)
		s := loadNotifierSettings(l, common)
		return s, l.Err()
	}

	s, err := load(base(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.engine.PollInterval != 30*time.Second || s.engine.StallAfter != 15*time.Minute || s.engine.Batch != 100 ||
		s.engine.PublicAdminURL != "https://admin.example" || s.allowPrivate {
		t.Errorf("defaults %+v", s)
	}

	s, err = load(base(map[string]string{"PADDOCK_ENV": "development", "PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": "true",
		"PADDOCK_NOTIFY_POLL_INTERVAL": "5s", "PADDOCK_NOTIFY_STALL_AFTER": "1m", "PADDOCK_NOTIFY_BATCH": "1"}))
	if err != nil || !s.allowPrivate || s.engine.PollInterval != 5*time.Second || s.engine.Batch != 1 {
		t.Errorf("development: %+v, %v", s, err)
	}

	for name, env := range map[string]map[string]string{
		"PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": {"PADDOCK_ENV": "production", "PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE": "true"},
		"PADDOCK_NOTIFY_POLL_INTERVAL":       {"PADDOCK_NOTIFY_POLL_INTERVAL": "4s"},
		"PADDOCK_NOTIFY_STALL_AFTER":         {"PADDOCK_NOTIFY_STALL_AFTER": "59s"},
		"PADDOCK_NOTIFY_BATCH":               {"PADDOCK_NOTIFY_BATCH": "101"},
		"PADDOCK_PUBLIC_ADMIN_URL":           {"PADDOCK_PUBLIC_ADMIN_URL": ""},
	} {
		if _, err := load(base(env)); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	if _, err := load(base(map[string]string{"PADDOCK_NOTIFY_BATCH": "0"})); err == nil {
		t.Error("PADDOCK_NOTIFY_BATCH=0 accepted")
	}
}
