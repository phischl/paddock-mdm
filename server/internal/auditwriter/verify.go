package auditwriter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
)

// PublicKeys returns the audit-chain public keys by version.
type PublicKeys func(ctx context.Context) (map[int][]byte, error)

// Verifier checks the hash chain and every object of a range of days.
type Verifier struct {
	pool  *db.AuditWriterPool
	store ObjectStore
	keys  PublicKeys
}

// NewVerifier creates a verifier.
func NewVerifier(pool *db.AuditWriterPool, store ObjectStore, keys PublicKeys) *Verifier {
	return &Verifier{pool: pool, store: store, keys: keys}
}

// Report lists every problem found; it is empty when the chain verifies.
type Report struct {
	Days     int
	Objects  int
	Problems []string
}

// OK reports whether nothing was found.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

func (r *Report) addf(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Verify checks, for org and every day in [from, to]: a manifest exists (a missing day breaks the chain), its
// stored copy matches the index, its signature verifies with the audit-chain public key, it links to the previous
// day's manifest, it lists exactly the indexed objects, and every object's SHA-256 matches.
func (v *Verifier) Verify(ctx context.Context, org uuid.UUID, from, to time.Time) (*Report, error) {
	from, to = dayOf(from), dayOf(to)
	if to.Before(from) {
		return nil, fmt.Errorf("verify: --to is before --from")
	}
	keys, err := v.keys(ctx)
	if err != nil {
		return nil, err
	}
	report := &Report{}
	// Verification only reads and may take longer than a writer transaction is allowed to run, so it uses a plain
	// session. Sealed days receive no new objects, so the reads need no common snapshot.
	err = v.pool.WithSession(ctx, func(ctx context.Context, q *auditstore.Queries) error {
		manifests, err := q.ListAuditManifests(ctx, auditstore.ListAuditManifestsParams{OrganizationID: org, FromDay: from, ToDay: to})
		if err != nil {
			return err
		}
		byDay := map[string]auditstore.AuditManifest{}
		for _, m := range manifests {
			byDay[dayOf(m.Day).Format(time.DateOnly)] = m
		}
		var prev []byte
		if p, err := q.GetAuditManifest(ctx, auditstore.GetAuditManifestParams{OrganizationID: org, Day: from.AddDate(0, 0, -1)}); err == nil {
			prev = p.Sha256
		} else if !db.IsNoRows(err) {
			return err
		}
		first := true
		for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
			report.Days++
			name := day.Format(time.DateOnly)
			m, ok := byDay[name]
			if !ok {
				report.addf("%s: no manifest (chain broken)", name)
				prev = nil
				first = false
				continue
			}
			if (!first || prev != nil) && !bytes.Equal(m.PrevSha256, prev) {
				report.addf("%s: prev_manifest_sha256 does not link to the previous day", name)
			}
			first = false
			if err := v.verifyManifest(ctx, q, report, org, day, m, keys); err != nil {
				return err
			}
			prev = m.Sha256
		}
		return nil
	})
	return report, err
}

func (v *Verifier) verifyManifest(ctx context.Context, q *auditstore.Queries, report *Report, org uuid.UUID, day time.Time,
	m auditstore.AuditManifest, keys map[int][]byte) error {
	name := day.Format(time.DateOnly)
	raw, err := v.store.Get(ctx, m.ObjectKey)
	if err != nil {
		report.addf("%s: manifest object %s unreadable: %v", name, m.ObjectKey, err)
		return nil
	}
	var file ManifestFile
	if err := json.Unmarshal(raw, &file); err != nil {
		report.addf("%s: manifest object is not valid JSON", name)
		return nil
	}
	canonical, err := jcs.Transform(file.Manifest)
	if err != nil {
		report.addf("%s: manifest cannot be canonicalized", name)
		return nil
	}
	sum := sha256.Sum256(canonical)
	if !bytes.Equal(sum[:], m.Sha256) {
		report.addf("%s: stored manifest does not match the index hash", name)
	}
	if file.Signature != m.Signature || file.KeyVersion != int(m.KeyVersion) {
		report.addf("%s: stored signature differs from the index", name)
	}
	if !verifySignature(keys, file.KeyVersion, file.Signature, sum[:]) {
		report.addf("%s: signature does not verify with audit-chain v%d", name, file.KeyVersion)
	}
	var manifest Manifest
	if err := json.Unmarshal(canonical, &manifest); err != nil {
		report.addf("%s: manifest does not parse", name)
		return nil
	}
	if manifest.OrganizationID != org.String() || manifest.Day != name || manifest.Schema != ManifestSchema {
		report.addf("%s: manifest belongs to %s/%s", name, manifest.OrganizationID, manifest.Day)
	}
	wantPrev := ""
	if m.PrevSha256 != nil {
		wantPrev = hex.EncodeToString(m.PrevSha256)
	}
	if got := deref(manifest.PrevManifestSHA256); got != wantPrev {
		report.addf("%s: manifest prev hash differs from the index", name)
	}

	indexed, err := q.ListAuditObjectsForDay(ctx, auditstore.ListAuditObjectsForDayParams{OrganizationID: org, Day: day})
	if err != nil {
		return err
	}
	listed := map[string]ManifestObject{}
	for _, o := range manifest.Objects {
		listed[o.Key] = o
	}
	for _, o := range indexed {
		if _, ok := listed[o.ObjectKey]; !ok {
			report.addf("%s: indexed object %s is missing from the manifest", name, o.ObjectKey)
		}
	}
	for _, o := range manifest.Objects {
		report.Objects++
		if !strings.HasPrefix(o.Key, "org/"+org.String()+"/") {
			report.addf("%s: object %s is outside the organization prefix", name, o.Key)
		}
		body, err := v.store.Get(ctx, o.Key)
		if err != nil {
			report.addf("%s: object %s unreadable: %v", name, o.Key, err)
			continue
		}
		got := sha256.Sum256(body)
		if hex.EncodeToString(got[:]) != o.SHA256 {
			report.addf("%s: object %s was modified (SHA-256 mismatch)", name, o.Key)
		}
	}
	return nil
}

// verifySignature checks an OpenBao Transit ed25519 signature "vault:v<N>:<base64>".
func verifySignature(keys map[int][]byte, version int, sig string, message []byte) bool {
	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 || parts[1] != fmt.Sprintf("v%d", version) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	pub, ok := keys[version]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, message, raw)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
