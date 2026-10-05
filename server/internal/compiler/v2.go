package compiler

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/sudoers"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/domain/organization"
	"github.com/paddock-mdm/paddock/server/internal/domain/privilege"
)

// PrivilegedGroups are the local groups whose membership the agent reconciles (architecture §10.1).
var PrivilegedGroups = []string{"sudo", "admin", "wheel"}

// SudoersValidator checks a rendered sudoers file before the bundle is signed (plan M3a decision 16).
type SudoersValidator interface {
	Validate(ctx context.Context, content []byte) error
}

// Visudo validates with `visudo -cf` in the compiler container.
type Visudo struct{ Path string }

// Validate runs visudo -cf - with content on stdin, so no temporary file is needed; the error carries visudo's
// output.
func (v Visudo) Validate(ctx context.Context, content []byte) error {
	cmd := exec.CommandContext(ctx, v.Path, "-cf", "-") //nolint:gosec // fixed binary from the configuration
	cmd.Stdin = bytes.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("visudo: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// renderFailure is a sudo entry that did not pass the server-side check; the device keeps its previous bundle.
type renderFailure struct {
	device   uuid.UUID
	username string
	reason   string
}

// renderV2 returns the login and sudo resources of a device (bundle schema v2, plan M3a decisions 15 and 16). A
// device of an organization without a primary domain gets no login resource. Every sudo entry is rendered with the
// reference renderer and the placeholder UID and checked by the validator; a failure blocks the device's bundle.
func (c *Compiler) renderV2(ctx context.Context, id *app.Identity, t compileTarget) ([]bundle.Resource, *renderFailure, error) {
	var out []bundle.Resource
	s := id.Settings
	breakGlass := slices.Clone(s.BreakGlassAccounts)
	if domain := organization.PrimaryDomain(id.Org.Domains); domain != "" {
		client := organization.DeviceLoginApp(id.Org.Slug)
		login, err := bundle.LoginResource(bundle.LoginSpec{
			Provider: bundle.ProviderHimmelblau,
			Himmelblau: bundle.HimmelblauSpec{
				OIDCIssuerURL: c.cfg.AuthentikURL + "/application/o/" + client + "/", AppID: client, Domain: domain,
				PamAllowGroups: id.AllowList(t.id, t.suspended), EnableHello: s.HelloEnabled,
				HelloPinMinLength: int(s.HelloPinMinLength), PackageVersion: c.cfg.HimmelblauVersion,
			},
			Suspended: t.suspended, LockedUsers: id.LockedUsernames(t.id), SessionAction: s.UserLockSessionAction,
			BreakGlassAccounts: breakGlass,
		})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, login)
	}
	groups := id.DeviceGroups(t.id)
	var entries []sudoers.Entry
	for _, u := range id.AllowedUsers(t.id) {
		e := id.Effective(u, groups)
		if e.Class == privilege.ClassNone {
			continue
		}
		username := id.Users[u].Username
		entry, ok, err := e.SudoEntry(username)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		// Only the classic flavor is validated: the sudo-rs flavor is the same file without the lecture_file setting
		// (pkg/sudoers tests), and the sudo-rs of Debian 13 parses settings differently from the one devices run.
		rendered, err := sudoers.Render(entry, sudoers.PlaceholderUID, sudoers.Classic)
		if err == nil {
			err = c.cfg.Sudoers.Validate(ctx, rendered)
		}
		if err != nil {
			return nil, &renderFailure{device: t.id, username: username, reason: err.Error()}, nil
		}
		entries = append(entries, entry)
	}
	sudo, err := bundle.SudoResource(bundle.SudoSpec{
		LectureText: s.SudoLectureText, Entries: entries, PrivilegedGroups: PrivilegedGroups,
		SudoersDAllowlist: slices.Clone(s.SudoersDAllowlist), BreakGlassAccounts: breakGlass,
	})
	if err != nil {
		return nil, nil, err
	}
	return append(out, sudo), nil, nil
}
