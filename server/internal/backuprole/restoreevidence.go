package backuprole

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/auditpg/auditstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
)

// EscrowOrganizations returns the organizations whose escrowed LUKS headers the set at root holds, sorted. An
// organization or device segment that is not a canonical UUID is an error: the audit index could not be asked about
// it, or its evidence would miss the header's "<org>/<device>" key, and a header nobody can check must not be put back
// (decisions-alpha9 item 44, fail closed).
func EscrowOrganizations(root *os.Root) ([]uuid.UUID, error) {
	idx, err := indexRepo(root)
	if err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	for _, p := range idx.under(backupset.EscrowKey("")) {
		dev := escrowDevice(p)
		if dev == "" {
			continue
		}
		orgSeg, devSeg, _ := strings.Cut(dev, "/")
		org, err := canonicalUUID(orgSeg)
		if err != nil {
			return nil, fmt.Errorf("escrowed header %s: the organization is not a UUID", p)
		}
		if _, err := canonicalUUID(devSeg); err != nil {
			return nil, fmt.Errorf("escrowed header %s: the device is not a UUID", p)
		}
		seen[org] = true
	}
	out := make([]uuid.UUID, 0, len(seen))
	for org := range seen {
		out = append(out, org)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// AuditEscrowEvidence reads, by "<org>/<device>", the time of every device's newest successful Destroy of orgs from
// the audit index (role paddock_audit_reader, per organization through its row-level security). The audit index
// survives a restore, the restored control-plane database does not hold a Destroy newer than its recovery point
// (decisions-alpha9 items 39 and 44). Any error is returned: the caller fails closed.
func AuditEscrowEvidence(ctx context.Context, reader *db.AuditReader, orgs []uuid.UUID) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for _, org := range orgs {
		octx := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "restore", OrganizationID: org})
		err := reader.InOrg(octx, func(ctx context.Context, q *auditstore.Queries) error {
			rows, err := q.EscrowDestroyEvidence(ctx, org)
			if err != nil {
				return err
			}
			for _, r := range rows {
				out[org.String()+"/"+r.DeviceID] = r.DestroyedAt.UTC()
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return out, nil
}

// canonicalUUID parses s and refuses any spelling other than the lower-case hyphenated form every producer writes,
// because the evidence is matched on that exact string.
func canonicalUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, err
	}
	if id.String() != s {
		return uuid.Nil, fmt.Errorf("%q is not the canonical form %s", s, id)
	}
	return id, nil
}
