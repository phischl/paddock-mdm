package compiler

import (
	"bytes"
	"context"
	"errors"
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

// omittedEntry is a sudo entry left out of a bundle because a profile stored before the command check was tightened
// contributes a command that fails it (plan M3.1 decision 1), or because the username is one devices must not pass
// to a tool, e.g. a synced user whose name starts with '-' (plan M4a step 0a); the user gets no sudo rights on the
// device until the profile or the name is fixed.
type omittedEntry struct {
	username string
	reason   string
}

// renderV2 returns the login and sudo resources of a device (bundle schema v2, plan M3a decisions 15 and 16). A
// device of an organization without a primary domain gets no login resource. A sudo entry with an invalid command or
// username is omitted; every other entry is rendered with the reference renderer and the placeholder UID and checked by the
// validator, and a failure blocks the device's bundle.
func (c *Compiler) renderV2(ctx context.Context, id *app.Identity, t compileTarget) ([]bundle.Resource, []omittedEntry, *renderFailure, error) {
	var out []bundle.Resource
	s := id.Settings
	// The managed local administrator is a break-glass account everywhere: never denied, never removed from the
	// privileged groups (plan M4a decision 14).
	breakGlass := slices.Clone(s.BreakGlassAccounts)
	if !slices.Contains(breakGlass, s.LocalAdminUsername) {
		breakGlass = append(breakGlass, s.LocalAdminUsername)
	}
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
			LocalAdmin:         &bundle.LocalAdminSpec{Username: s.LocalAdminUsername, RotationDays: int(s.LocalAdminRotationDays)},
		})
		if err != nil {
			return nil, nil, nil, err
		}
		out = append(out, login)
	}
	groups := id.DeviceGroups(t.id)
	var entries []sudoers.Entry
	var omitted []omittedEntry
	for _, u := range id.AllowedUsers(t.id) {
		e := id.Effective(u, groups)
		if e.Class == privilege.ClassNone {
			continue
		}
		username := id.Users[u].Username
		entry, ok, err := e.SudoEntry(username)
		if err != nil {
			return nil, nil, nil, err
		}
		if !ok {
			continue
		}
		if errors.Is(sudoers.Validate(entry), sudoers.ErrUsername) {
			omitted = append(omitted, omittedEntry{username: username, reason: sudoers.ErrUsername.Error()})
			continue
		}
		if bad := privilege.InvalidCommands(entry.Commands); len(bad) > 0 {
			omitted = append(omitted, omittedEntry{username: username, reason: invalidCommandReason(id, e, bad[0])})
			continue
		}
		// Only the classic flavor is validated: the sudo-rs flavor is the same file without the lecture_file setting
		// (pkg/sudoers tests), and the sudo-rs of Debian 13 parses settings differently from the one devices run.
		rendered, err := sudoers.Render(entry, sudoers.PlaceholderUID, sudoers.Classic)
		if err == nil {
			err = c.cfg.Sudoers.Validate(ctx, rendered)
		}
		if err != nil {
			return nil, nil, &renderFailure{device: t.id, username: username, reason: err.Error()}, nil
		}
		entries = append(entries, entry)
	}
	sudo, err := bundle.SudoResource(bundle.SudoSpec{
		LectureText: s.SudoLectureText, Entries: entries, PrivilegedGroups: PrivilegedGroups,
		SudoersDAllowlist: slices.Clone(s.SudoersDAllowlist), BreakGlassAccounts: breakGlass,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return append(out, sudo), omitted, nil, nil
}

// invalidCommandReason names the invalid command, why it is invalid and the profiles it comes from.
func invalidCommandReason(id *app.Identity, e privilege.EffectiveProfile, command string) string {
	var names []string
	for _, d := range e.Derivation {
		if d.Kind != privilege.DerivedCommand || d.Item != command {
			continue
		}
		for _, p := range id.Profiles {
			if p.ID == d.ProfileID && !slices.Contains(names, p.Name) {
				names = append(names, p.Name)
			}
		}
	}
	return fmt.Sprintf("command %q of profile %s: %v", command, strings.Join(names, ", "), sudoers.ValidateCommand(command))
}
