// Package selftest is `paddockd self-test` (plan M2b decision 14): the checks the supervisor runs on a new agent
// version before it switches to it (design contract 3). It only reads; it never changes the device.
package selftest

import (
	"context"
	"errors"
	"os"

	"github.com/phischl/paddock-mdm/agent/internal/apply"
	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/client"
	"github.com/phischl/paddock-mdm/agent/internal/config"
	"github.com/phischl/paddock-mdm/agent/internal/identity"
	"github.com/phischl/paddock-mdm/agent/internal/paths"
	"github.com/phischl/paddock-mdm/agent/internal/state"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Check results.
const (
	Pass         = "pass"
	Fail         = "fail"
	Skipped      = "skipped"
	Inconclusive = "inconclusive"
)

// Check is one self-test check.
type Check struct {
	Name    string `json:"name"`
	Result  string `json:"result"`
	Message string `json:"message,omitempty"`
}

// Report is the JSON report on stdout.
type Report struct {
	Version string  `json:"version"`
	OK      bool    `json:"ok"`
	Checks  []Check `json:"checks"`
}

// Run executes all checks. The report is OK when no check failed; an unreachable server is inconclusive.
func Run(ctx context.Context, l paths.Layout) Report {
	r := Report{Version: buildinfo.Version}
	add := func(name string, err error) {
		c := Check{Name: name, Result: Pass}
		if err != nil {
			c.Result, c.Message = Fail, err.Error()
		}
		r.Checks = append(r.Checks, c)
	}
	add("binary", nil)
	if buildinfo.BrokenSelfTest {
		add("test_build", errors.New("built with paddock_testbroken_selftest"))
	}
	cfg, cfgErr := config.LoadAgent(l.AgentConfig())
	add("agent_config", cfgErr)
	trust, trustErr := config.LoadTrust(l.Trust())
	add("trust", trustErr)
	key, keyErr := identity.Load(l.IdentityKey())
	add("identity_key", keyErr)
	st, stErr := state.Load(l.State())
	add("state", stErr)
	r.Checks = append(r.Checks, bundleCheck(l, trust, cfg, st, errors.Join(trustErr, cfgErr, stErr)))
	r.Checks = append(r.Checks, serverCheck(ctx, cfg, key, errors.Join(cfgErr, keyErr)))
	r.OK = true
	for _, c := range r.Checks {
		if c.Result == Fail {
			r.OK = false
		}
	}
	return r
}

// bundleCheck verifies the cached last applied bundle, if there is one.
func bundleCheck(l paths.Layout, trust bundle.Trust, cfg config.Agent, st state.State, prereq error) Check {
	c := Check{Name: "bundle", Result: Pass}
	env, err := os.ReadFile(l.Bundle())
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.Result, c.Message = Skipped, "no bundle applied yet"
	case err != nil:
		c.Result, c.Message = Fail, err.Error()
	case prereq != nil:
		c.Result, c.Message = Skipped, "configuration unreadable"
	default:
		if _, err := bundle.VerifyVersions(env, trust, st.DeviceID, cfg.OrganizationID, st.AppliedBundleVersion-1, apply.SchemaVersions); err != nil {
			c.Result, c.Message = Fail, err.Error()
		}
	}
	return c
}

// serverCheck tries to reach the server; failing to reach it is inconclusive, not a failure (fail safe: an update
// must not be blocked by a server outage, and must not be rolled back because of one).
func serverCheck(ctx context.Context, cfg config.Agent, key identity.Key, prereq error) Check {
	c := Check{Name: "server", Result: Pass}
	if prereq != nil {
		c.Result, c.Message = Skipped, "configuration unreadable"
		return c
	}
	cl, err := client.New(cfg.ServerURL, cfg.Proxy, key)
	if err == nil {
		err = cl.Reachable(ctx)
	}
	if err != nil {
		c.Result, c.Message = Inconclusive, err.Error()
	}
	return c
}
