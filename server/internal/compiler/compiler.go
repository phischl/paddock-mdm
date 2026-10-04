// Package compiler is the compiler role: it consumes state changes, renders the desired state of every affected
// active device, and publishes a new signed bundle when the content changed (architecture §7.1, plan M2a
// decision 13). Bundles are recomputed on change, never per request.
package compiler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/dsse"
	"github.com/paddock-mdm/paddock/server/internal/adapters/postgres/pgstore"
	"github.com/paddock-mdm/paddock/server/internal/app"
	"github.com/paddock-mdm/paddock/server/internal/bundlesign"
	"github.com/paddock-mdm/paddock/server/internal/devicecache"
	"github.com/paddock-mdm/paddock/server/internal/domain/device"
	"github.com/paddock-mdm/paddock/server/internal/domain/managedconfig"
	"github.com/paddock-mdm/paddock/server/internal/domain/statechange"
	"github.com/paddock-mdm/paddock/server/internal/platform/bao"
	"github.com/paddock-mdm/paddock/server/internal/platform/db"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

var (
	metricBundles = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "paddock_compiler_bundles_total", Help: "Compiled devices by result (new, unchanged, failed).",
	}, []string{"result"})
	metricLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "paddock_compiler_latency_seconds", Help: "Time from the oldest state change of a batch to its published bundles.",
		Buckets: prometheus.ExponentialBuckets(0.25, 2, 10),
	})
)

// CheckinIntervalS is the check-in interval written into every bundle.
const CheckinIntervalS = 300

// Signer signs with a Transit key (bao.Client).
type Signer interface {
	SignBatch(ctx context.Context, key string, messages [][]byte) ([]bao.RawSignature, error)
}

// Store uploads bundle objects (objectstore.Store).
type Store interface {
	Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error
}

// Compiler renders, signs and uploads bundles.
type Compiler struct {
	pool   *db.OrgPool
	signer Signer
	store  Store
	cache  *devicecache.Cache
	now    func() time.Time
}

// New creates a compiler.
func New(pool *db.OrgPool, signer Signer, store Store, cache *devicecache.Cache) *Compiler {
	return &Compiler{pool: pool, signer: signer, store: store, cache: cache, now: time.Now}
}

// ObjectKey is the object of a bundle version (architecture §7.1).
func ObjectKey(org, dev uuid.UUID, version int64) string {
	return fmt.Sprintf("org/%s/devices/%s/bundles/%d.dsse", org, dev, version)
}

// Compile recompiles the active devices in the scopes of events, organization by organization.
func (c *Compiler) Compile(ctx context.Context, events []statechange.Event) error {
	byOrg := map[uuid.UUID][]statechange.Event{}
	var orgs []uuid.UUID
	for _, ev := range events {
		if byOrg[ev.OrganizationID] == nil {
			orgs = append(orgs, ev.OrganizationID)
		}
		byOrg[ev.OrganizationID] = append(byOrg[ev.OrganizationID], ev)
	}
	for _, org := range orgs {
		if err := c.compileOrg(systemContext(ctx, org), org, byOrg[org]); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

func systemContext(ctx context.Context, org uuid.UUID) context.Context {
	return principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "compiler", OrganizationID: org})
}

// rendered is the new bundle of one device, before signing.
type rendered struct {
	device  uuid.UUID
	oldSeq  int64
	content [32]byte
	payload []byte
}

func (c *Compiler) compileOrg(ctx context.Context, org uuid.UUID, events []statechange.Event) error {
	var todo []rendered
	err := c.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		ids, err := expand(ctx, q, events)
		if err != nil || len(ids) == 0 {
			return err
		}
		targets, err := q.ListCompileTargets(ctx, ids)
		if err != nil {
			return err
		}
		defs, err := app.LoadManagedDefinitions(ctx, q)
		if err != nil {
			return err
		}
		for _, t := range targets {
			r, changed, err := c.render(ctx, q, org, t, defs)
			if err != nil {
				return fmt.Errorf("render %s: %w", t.ID, err)
			}
			if changed {
				todo = append(todo, r)
			}
		}
		return nil
	})
	if err != nil || len(todo) == 0 {
		return err
	}
	return c.publish(ctx, org, todo)
}

// expand turns the scopes of events into the IDs of the affected devices; only active devices are compiled.
func expand(ctx context.Context, q *pgstore.Queries, events []statechange.Event) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]bool{}
	var ids []uuid.UUID
	add := func(more []uuid.UUID) {
		for _, id := range more {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	for _, ev := range events {
		switch ev.Scope {
		case statechange.ScopeOrg:
			all, err := q.ListActiveDeviceIDs(ctx)
			if err != nil {
				return nil, err
			}
			add(all)
		case statechange.ScopeDeviceGroup:
			members, err := q.ListActiveGroupMemberIDs(ctx, ev.ID)
			if err != nil {
				return nil, err
			}
			add(members)
		case statechange.ScopeDevice:
			add([]uuid.UUID{ev.ID})
		}
	}
	return ids, nil
}

// render builds the next bundle of an active device and reports whether its content differs from the last one.
func (c *Compiler) render(ctx context.Context, q *pgstore.Queries, org uuid.UUID, t pgstore.ListCompileTargetsRow,
	defs app.ManagedDefinitions) (rendered, bool, error) {
	if !device.Compiled(t.State) {
		return rendered{}, false, nil
	}
	groups, err := q.ListDeviceGroupIDsOfDevice(ctx, t.ID)
	if err != nil {
		return rendered{}, false, err
	}
	resources, err := managedconfig.Resources(defs.Resolve(groups))
	if err != nil {
		return rendered{}, false, err
	}
	b := bundle.Bundle{
		SchemaVersion: bundle.SchemaVersion, BundleVersion: t.BundleSeq + 1, DeviceID: t.ID.String(),
		OrganizationID: org.String(), IssuedAt: c.now().UTC().Truncate(time.Second),
		Agent: bundle.AgentCfg{CheckinIntervalS: CheckinIntervalS}, Resources: resources,
	}
	content, err := bundle.ContentSHA256(b)
	if err != nil {
		return rendered{}, false, err
	}
	latest, err := q.GetLatestBundle(ctx, t.ID)
	switch {
	case err == nil && bytes.Equal(latest.ContentSha256, content[:]):
		metricBundles.WithLabelValues("unchanged").Inc()
		return rendered{}, false, nil
	case err != nil && !db.IsNoRows(err):
		return rendered{}, false, err
	}
	payload, err := bundle.Encode(b)
	if err != nil {
		return rendered{}, false, err
	}
	return rendered{device: t.ID, oldSeq: t.BundleSeq, content: content, payload: payload}, true, nil
}

// publish signs all bundles in one batch, then per device increments bundle_seq, records the bundle row and uploads
// the envelope in one transaction, and finally points bp: at it. An upload failure rolls the transaction back, so
// the version is reused on retry and bp: only ever points to uploaded bundles.
func (c *Compiler) publish(ctx context.Context, org uuid.UUID, todo []rendered) error {
	pae := make([][]byte, len(todo))
	for i, r := range todo {
		pae[i] = dsse.PAE(bundle.PayloadType, r.payload)
	}
	sigs, err := c.signer.SignBatch(ctx, bundlesign.KeyName, pae)
	if err != nil {
		return err
	}
	var errs []error
	for i, r := range todo {
		env, err := dsse.New(bundle.PayloadType, r.payload, dsse.Signature{
			KeyID: bundlesign.KeyID(sigs[i].KeyVersion), Sig: base64.StdEncoding.EncodeToString(sigs[i].Value),
		}).Encode()
		if err == nil {
			err = c.commit(ctx, org, r, env)
		}
		if err != nil {
			metricBundles.WithLabelValues("failed").Inc()
			errs = append(errs, fmt.Errorf("device %s: %w", r.device, err))
			continue
		}
		metricBundles.WithLabelValues("new").Inc()
	}
	return errors.Join(errs...)
}

// commit records and uploads one bundle and updates its pointer.
func (c *Compiler) commit(ctx context.Context, org uuid.UUID, r rendered, envelope []byte) error {
	version := r.oldSeq + 1
	key := ObjectKey(org, r.device, version)
	sum := sha256.Sum256(envelope)
	err := c.pool.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		n, err := q.SetDeviceBundleSeq(ctx, pgstore.SetDeviceBundleSeqParams{ID: r.device, OldSeq: r.oldSeq, NewSeq: version})
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("bundle_seq changed concurrently")
		}
		if err := q.InsertBundle(ctx, pgstore.InsertBundleParams{
			DeviceID: r.device, Version: version, OrganizationID: org, ContentSha256: r.content[:],
			EnvelopeSha256: sum[:], ObjectKey: key,
		}); err != nil {
			return err
		}
		return c.store.Put(ctx, key, "application/vnd.dsse.envelope.v1+json", "private, max-age=120", envelope)
	})
	if err != nil {
		return err
	}
	if err := c.cache.PutBundlePointer(ctx, r.device, devicecache.BundlePointer{
		Version: version, SHA256: hex.EncodeToString(sum[:]), ObjectKey: key,
	}); err != nil {
		// Committed and uploaded; the reconcile loop sets the pointer.
		slog.WarnContext(ctx, "setting bundle pointer failed; the reconcile loop repairs it", "device_id", r.device, "error", err)
	}
	slog.InfoContext(ctx, "bundle published", "organization_id", org, "device_id", r.device, "version", version)
	return nil
}
