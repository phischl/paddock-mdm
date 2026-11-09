// Package selfservice is the agent's side of self-service (plan M13b decisions 11–14, ADR 0049 decisions 2, 3, 6, 7
// and 8): a JSON-over-HTTP server on the world-connectable unix socket /run/paddock/selfservice.sock that identifies
// the caller by the kernel's peer credentials, authorizes every request against the applied, signed bundle only, and
// queues the operations a user asks for to one executor that runs them with the software reconciler's primitives.
package selfservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/agent/internal/getent"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/bundle"
)

// Himmelblau's idmap range (plan M13b §2): a UID in it is a directory user, every other UID a local account.
const (
	DirectoryUIDMin = 200000
	DirectoryUIDMax = 999999999
)

// Principal is the account a request comes from. UPN is the lower-cased user principal name of a directory user, ""
// for a local account (which then sees only what is offered to everyone). UID 0 is an ordinary local account.
type Principal struct {
	UID       int
	Name      string
	UPN       string
	Directory bool
}

// User is the user name events and the record carry: the UPN of a directory user, the account name otherwise.
func (p Principal) User() string {
	if p.UPN != "" {
		return p.UPN
	}
	return p.Name
}

// errUnknownUser refuses a caller whose UID does not resolve to exactly one account.
var errUnknownUser = errors.New("the caller's UID resolves to no account")

// Authorize resolves the UID of the peer credentials to a principal (plan M13b decision 11): `getent passwd <uid>`
// names the account; a directory user whose name lacks the domain (Himmelblau may list short names) gets the UPN
// name@domain only when that name resolves to the same UID, the rule of session.login.
func Authorize(ctx context.Context, sys reconcile.System, uid int, domain string) (Principal, error) {
	if uid < 0 {
		return Principal{}, errUnknownUser
	}
	pw, err := lookup(ctx, sys, strconv.Itoa(uid))
	if err != nil || int64(pw.UID) != int64(uid) {
		return Principal{}, fmt.Errorf("%w: UID %d", errUnknownUser, uid)
	}
	p := Principal{UID: uid, Name: pw.Name, Directory: uid >= DirectoryUIDMin && uid <= DirectoryUIDMax}
	if !p.Directory {
		return p, nil
	}
	name := strings.ToLower(pw.Name)
	switch {
	case strings.Contains(name, "@"):
		p.UPN = name
	case domain != "":
		candidate := name + "@" + strings.ToLower(domain)
		if cpw, err := lookup(ctx, sys, candidate); err == nil && int64(cpw.UID) == int64(uid) {
			p.UPN = candidate
		}
	}
	if !bundle.ValidAudienceUser(p.UPN) {
		p.UPN = ""
	}
	return p, nil
}

func lookup(ctx context.Context, sys reconcile.System, key string) (getent.Passwd, error) {
	out, exit, err := sys.Getent(ctx, "passwd", key)
	if err != nil {
		return getent.Passwd{}, err
	}
	if exit != 0 {
		return getent.Passwd{}, fmt.Errorf("getent passwd %s: exit %d", key, exit)
	}
	return getent.ParsePasswd(out)
}

// inAudience reports whether an available package is offered to p: to everyone, or to p's UPN.
func inAudience(pkg bundle.SoftwarePackage, p Principal) bool {
	a := pkg.Audience
	return pkg.Intent == bundle.SoftwareAvailable && a != nil && (a.All || p.UPN != "" && slices.Contains(a.Users, p.UPN))
}

// managed reports whether a package is policy and so read-only for the user.
func managed(pkg bundle.SoftwarePackage) bool { return pkg.Intent != bundle.SoftwareAvailable }

// visible reports whether p may see a package (plan M13b decision 11, ADR 0049 decision 2): an available package of
// p's audience, and every managed one except the packages the compiler adds itself and a user-scope application
// targeted at other users. Nothing else is named to p, so p learns nothing about what other users are offered.
func visible(pkg bundle.SoftwarePackage, p Principal) bool {
	switch {
	case pkg.CatalogEntryID == bundle.SoftwareRuntimeEntryID:
		return false
	case !managed(pkg):
		return inAudience(pkg, p)
	case pkg.Users != nil:
		return p.UPN != "" && slices.Contains(*pkg.Users, p.UPN)
	}
	return true
}

// find returns the first package of entryID that p may see.
func find(sp bundle.SoftwareSpec, entryID string, p Principal) (bundle.SoftwarePackage, bool) {
	for _, pkg := range sp.Packages {
		if pkg.CatalogEntryID == entryID && visible(pkg, p) {
			return pkg, true
		}
	}
	return bundle.SoftwarePackage{}, false
}

// samePackage reports whether two packages name the same application.
func samePackage(a, b bundle.SoftwarePackage) bool {
	return a.Package == b.Package && a.FlatpakRef == b.FlatpakRef
}

// userScoped reports whether a package is installed per user.
func userScoped(pkg bundle.SoftwarePackage) bool {
	return pkg.FlatpakRef != "" && pkg.Scope == bundle.SoftwareScopeUser
}

// scope is the scope events and views name.
func scope(pkg bundle.SoftwarePackage) string {
	if userScoped(pkg) {
		return bundle.SoftwareScopeUser
	}
	return bundle.SoftwareScopeSystem
}
