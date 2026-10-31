package app

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Privileged actions on notification destinations (plan M9 decision 14): organization destinations belong to the
// organization administrators, platform destinations to the platform administrators; every change needs a step-up.
var (
	SpecNotificationCreate           = ActionSpec{Code: audit.CodeNotificationDestinationCreated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecNotificationUpdate           = ActionSpec{Code: audit.CodeNotificationDestinationUpdated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecNotificationDelete           = ActionSpec{Code: audit.CodeNotificationDestinationDeleted, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecNotificationRotateSecret     = ActionSpec{Code: audit.CodeNotificationDestinationSecretRotated, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecNotificationTest             = ActionSpec{Code: audit.CodeNotificationTestRequested, AllowedRoles: RolesAdmin, RequiresStepUp: true}
	SpecNotificationResolvePseudonym = ActionSpec{Code: audit.CodeNotificationPseudonymResolved, AllowedRoles: RolesAdmin, RequiresStepUp: true}

	SpecPlatformNotificationCreate       = ActionSpec{Code: audit.CodeNotificationDestinationCreated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecPlatformNotificationUpdate       = ActionSpec{Code: audit.CodeNotificationDestinationUpdated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecPlatformNotificationDelete       = ActionSpec{Code: audit.CodeNotificationDestinationDeleted, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecPlatformNotificationRotateSecret = ActionSpec{Code: audit.CodeNotificationDestinationSecretRotated, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecPlatformNotificationTest         = ActionSpec{Code: audit.CodeNotificationTestRequested, AllowedRoles: RolesPlatform, RequiresStepUp: true}
)

// Transit keys of the notification secrets (plan M9 amendment section E): notification-wrap encrypts the webhook URL
// and signing secret, notification-pseudonym wraps the organization's pseudonym key. Only the notifier decrypts.
const (
	NotificationWrapKey      = "notification-wrap"
	NotificationPseudonymKey = "notification-pseudonym"
)

// Cursor choices when a disabled destination is enabled again (plan M9 decision 16).
const (
	CursorContinue = "continue"
	CursorSkip     = "skip"
)

// NotificationKeys encrypts the destination secrets for the notifier (the bao client). The organization and field
// form the Transit context, so a ciphertext decrypts for its own organization and field only.
type NotificationKeys interface {
	Encrypt(ctx context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error)
	WrappedDataKey(ctx context.Context, key string, org uuid.UUID, field bao.ContextField) (string, error)
}

// Notifications are the use cases of the notification destinations of organizations and the platform. The scope is
// the route's: organization routes run in ScopeOrg, platform routes in ScopePlatform (nil organization).
type Notifications struct {
	runner       *ActionRunner
	org          *db.OrgPool
	platform     *db.PlatformPool
	keys         NotificationKeys
	urls         outbound.Policy
	emailEnabled bool
	now          func() time.Time
}

// NewNotifications creates the use cases. urls is the webhook URL policy (the development stack admits private
// addresses), emailEnabled says whether the installation has an SMTP relay (PADDOCK_SMTP_ENABLED).
func NewNotifications(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, keys NotificationKeys,
	urls outbound.Policy, emailEnabled bool) *Notifications {
	return &Notifications{runner: runner, org: org, platform: platform, keys: keys, urls: urls, emailEnabled: emailEnabled, now: time.Now}
}

// NotificationDestinationInput are the writable fields of a destination. URL is the plaintext webhook URL; on an
// update nil keeps the stored URL. Cursor is required when an update enables a disabled destination.
type NotificationDestinationInput struct {
	Type               outbound.Type
	Name               string
	Enabled            bool
	FilterMode         outbound.FilterMode
	Codes              []string
	PseudonymizeUsers  bool
	IncludeParams      bool
	URL                *string
	HeartbeatIntervalS int
	Recipients         []string
	EmailMinIntervalS  int
	Cursor             string
}

// NotificationDestination is a destination as the API shows it: never the URL or the secret.
type NotificationDestination struct {
	ID                 uuid.UUID
	Type               string
	Name               string
	Enabled            bool
	FilterMode         string
	Codes              []string
	PseudonymizeUsers  bool
	IncludeParams      bool
	URLDisplay         *string
	HeartbeatIntervalS int
	Recipients         []string
	EmailMinIntervalS  int
	CreatedBy          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	State              NotificationDestinationState
}

// NotificationDestinationState is the delivery state the notifier keeps. LagSeconds is how long deliveries have been
// failing (since the first failure of the current series), 0 while they succeed.
type NotificationDestinationState struct {
	Status          string
	CursorCommitSeq int64
	ForwardSeq      int64
	LastSuccessAt   *time.Time
	LastAttemptAt   *time.Time
	NextAttemptAt   *time.Time
	StalledSince    *time.Time
	LastError       *string
	LagSeconds      int64
	LastTest        *NotificationTestResult
}

// NotificationTestResult is the outcome of the last test delivery.
type NotificationTestResult struct {
	At    time.Time
	OK    bool
	Error *string
}

// NotificationQuery selects one page of destinations.
type NotificationQuery struct {
	Page    ListPage
	Types   []string // webhook, email; nil: all
	Enabled *bool
}

// PseudonymLookup is the result of a pseudonym lookup; Username is set once Resolved ("" when no user matches).
type PseudonymLookup struct {
	Pseudonym string
	Username  *string
	Resolved  bool
}

// pseudonymPattern is the form of outbound.Pseudonym.
var pseudonymPattern = regexp.MustCompile(`^u_[0-9a-f]{24}$`)

// Capabilities reports which destination types the installation supports: e-mail only with an SMTP relay.
func (n *Notifications) Capabilities(ctx context.Context) (email bool, err error) {
	p, ok := principal.From(ctx)
	switch {
	case !ok:
		return false, problem.Unauthenticated
	case p.Kind == principal.KindPlatformAdmin:
		return n.emailEnabled, nil
	}
	if _, err := RequireOrg(ctx, RolesAudit); err != nil {
		return false, err
	}
	return n.emailEnabled, nil
}

// List returns one page of the scope's destinations (organization: org_admin, org_auditor; platform: platform_admin).
func (n *Notifications) List(ctx context.Context, scope Scope, query NotificationQuery) (Listed[NotificationDestination], error) {
	var out Listed[NotificationDestination]
	if err := requireNotificationRead(ctx, scope); err != nil {
		return out, err
	}
	err := n.read(ctx, scope, func(ctx context.Context, q *pgstore.Queries) error {
		types := nilIfEmpty(query.Types)
		c, err := q.CountNotificationDestinations(ctx, pgstore.CountNotificationDestinationsParams{
			QPattern: query.Page.QPattern, Types: types, Enabled: query.Enabled, CountLimit: countLimit,
		})
		if err != nil {
			return fmt.Errorf("count notification destinations: %w", err)
		}
		out.Count = int(c)
		rows, err := q.ListNotificationDestinations(ctx, pgstore.ListNotificationDestinationsParams{
			QPattern: query.Page.QPattern, Types: types, Enabled: query.Enabled, Sort: query.Page.Sort,
			SkipRows: query.Page.Offset, MaxRows: query.Page.Limit,
		})
		if err != nil {
			return fmt.Errorf("list notification destinations: %w", err)
		}
		out.Items = make([]NotificationDestination, len(rows))
		for i, r := range rows {
			out.Items[i] = n.destination(pgstore.GetNotificationDestinationRow(r))
		}
		return nil
	})
	return out, err
}

// Get returns one destination of the scope; another scope's is not_found.
func (n *Notifications) Get(ctx context.Context, scope Scope, id uuid.UUID) (NotificationDestination, error) {
	var out NotificationDestination
	if err := requireNotificationRead(ctx, scope); err != nil {
		return out, err
	}
	err := n.read(ctx, scope, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetNotificationDestination(ctx, id)
		if err != nil {
			return notFound(err)
		}
		out = n.destination(row)
		return nil
	})
	return out, err
}

// Create creates a destination (audited: notification.destination_created) and returns the webhook signing secret
// once; neither the secret nor the URL is ever shown again (plan M9 decision 15).
func (n *Notifications) Create(ctx context.Context, scope Scope, in NotificationDestinationInput) (NotificationDestination, string, error) {
	var out NotificationDestination
	var secret string
	spec := withDestinationParams(scopedSpec(scope, SpecNotificationCreate, SpecPlatformNotificationCreate), in)
	err := n.runner.RunTx(ctx, scope, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if err := n.validate(ctx, scope, in, true, true); err != nil {
			return err
		}
		org := scopeOrganization(ctx, scope)
		id := uuid.Must(uuid.NewV7())
		params := pgstore.InsertNotificationDestinationParams{
			ID: id, OrganizationID: org, Type: string(in.Type), Name: in.Name, Enabled: in.Enabled,
			FilterMode: string(in.FilterMode), Codes: customCodes(in), PseudonymizeUsers: in.PseudonymizeUsers,
			IncludeParams: in.IncludeParams, HeartbeatIntervalS: int32(in.HeartbeatIntervalS), //nolint:gosec // validated 0 or 60–3600
			Recipients: nonNil(in.Recipients), EmailMinIntervalS: int32(emailInterval(in)), //nolint:gosec // validated 60–3600
			CreatedBy: actorDisplay(ctx),
		}
		if in.Type == outbound.TypeWebhook {
			plain, err := outbound.NewSecret()
			if err != nil {
				return err
			}
			urlCT, err := n.keys.Encrypt(ctx, NotificationWrapKey, org, bao.FieldURL, []byte(*in.URL))
			if err != nil {
				return fmt.Errorf("encrypt the webhook URL: %w", err)
			}
			secretCT, err := n.keys.Encrypt(ctx, NotificationWrapKey, org, bao.FieldSecret, []byte(plain))
			if err != nil {
				return fmt.Errorf("encrypt the signing secret: %w", err)
			}
			display := outbound.DisplayURL(*in.URL)
			params.UrlCiphertext, params.UrlDisplay, params.SecretCiphertext = &urlCT, &display, &secretCT
			secret = plain
		}
		if err := q.InsertNotificationDestination(ctx, params); err != nil {
			if db.IsUniqueViolation(err, "notification_destination_organization_id_name_key") {
				return problem.AlreadyExists.WithDetail("a notification destination with this name exists")
			}
			return err
		}
		if err := q.InsertNotificationDestinationState(ctx, pgstore.InsertNotificationDestinationStateParams{
			DestinationID: id, OrganizationID: org,
		}); err != nil {
			return err
		}
		if in.PseudonymizeUsers {
			if err := n.ensurePseudonymKey(ctx, q, org); err != nil {
				return err
			}
		}
		row, err := q.GetNotificationDestination(ctx, id)
		if err != nil {
			return err
		}
		out = n.destination(row)
		rec.SetTarget(destinationTarget(id, in.Name))
		return nil
	})
	if err != nil {
		return NotificationDestination{}, "", err
	}
	return out, secret, nil
}

// Update replaces a destination's settings (audited: notification.destination_updated). The type and the secret
// never change here; a missing URL keeps the stored one. Enabling a disabled destination needs a cursor choice:
// continue delivers the events since it was disabled, skip resumes at the newest event (plan M9 decision 16).
func (n *Notifications) Update(ctx context.Context, scope Scope, id uuid.UUID, in NotificationDestinationInput) (NotificationDestination, error) {
	var out NotificationDestination
	spec := withDestinationParams(scopedSpec(scope, SpecNotificationUpdate, SpecPlatformNotificationUpdate), in)
	spec.Params["cursor"] = in.Cursor
	// The type-dependent params come from the stored destination: the body may omit the type and the URL.
	for _, k := range []string{"type", "url_display", "recipient_count"} {
		delete(spec.Params, k)
	}
	err := n.runner.RunTx(ctx, scope, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		if _, err := q.LockNotificationDestination(ctx, id); err != nil {
			return notFound(err)
		}
		cur, err := q.GetNotificationDestination(ctx, id)
		if err != nil {
			return err
		}
		rec.SetTarget(destinationTarget(id, cur.Name))
		rec.SetParam("type", cur.Type)
		switch outbound.Type(cur.Type) {
		case outbound.TypeWebhook:
			display := ""
			if cur.UrlDisplay != nil {
				display = *cur.UrlDisplay
			}
			if in.URL != nil {
				display = outbound.DisplayURL(*in.URL)
			}
			rec.SetParam("url_display", display)
		case outbound.TypeEmail:
			rec.SetParam("recipient_count", len(in.Recipients))
		}
		if in.Type != "" && string(in.Type) != cur.Type {
			return problem.InvalidRequest.WithDetail("the type of a destination cannot change; create a new destination")
		}
		in.Type = outbound.Type(cur.Type)
		enabling := in.Enabled && !cur.Enabled
		if err := n.validate(ctx, scope, in, in.URL != nil, enabling); err != nil {
			return err
		}
		switch {
		case enabling && in.Cursor != CursorContinue && in.Cursor != CursorSkip:
			return problem.InvalidRequest.WithDetail("enabling a disabled destination requires cursor continue or skip")
		case !enabling && in.Cursor != "":
			return problem.InvalidRequest.WithDetail("cursor is only allowed when enabling a disabled destination")
		}
		org := scopeOrganization(ctx, scope)
		params := pgstore.UpdateNotificationDestinationParams{
			ID: id, Name: in.Name, Enabled: in.Enabled, FilterMode: string(in.FilterMode), Codes: customCodes(in),
			PseudonymizeUsers: in.PseudonymizeUsers, IncludeParams: in.IncludeParams,
			HeartbeatIntervalS: int32(in.HeartbeatIntervalS), //nolint:gosec // validated 0 or 60–3600
			Recipients:         nonNil(in.Recipients),
			EmailMinIntervalS:  int32(emailInterval(in)), //nolint:gosec // validated 60–3600
		}
		if in.URL != nil {
			ct, err := n.keys.Encrypt(ctx, NotificationWrapKey, org, bao.FieldURL, []byte(*in.URL))
			if err != nil {
				return fmt.Errorf("encrypt the webhook URL: %w", err)
			}
			display := outbound.DisplayURL(*in.URL)
			params.UrlCiphertext, params.UrlDisplay = &ct, &display
		}
		if err := q.UpdateNotificationDestination(ctx, params); err != nil {
			if db.IsUniqueViolation(err, "notification_destination_organization_id_name_key") {
				return problem.AlreadyExists.WithDetail("a notification destination with this name exists")
			}
			return err
		}
		if enabling && in.Cursor == CursorSkip {
			if err := n.startAtLatest(ctx, q, scope, id); err != nil {
				return err
			}
		}
		if in.PseudonymizeUsers && !cur.PseudonymizeUsers {
			if err := n.ensurePseudonymKey(ctx, q, org); err != nil {
				return err
			}
		}
		rec.SetParam("changed", changedFields(cur, in))
		row, err := q.GetNotificationDestination(ctx, id)
		if err != nil {
			return err
		}
		out = n.destination(row)
		return nil
	})
	return out, err
}

// Delete deletes a destination with its state and delivery history (audited: notification.destination_deleted).
func (n *Notifications) Delete(ctx context.Context, scope Scope, id uuid.UUID) error {
	spec := scopedSpec(scope, SpecNotificationDelete, SpecPlatformNotificationDelete)
	return n.runner.RunTx(ctx, scope, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockNotificationDestination(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(destinationTarget(id, cur.Name))
		rec.SetParam("name", cur.Name)
		rec.SetParam("type", cur.Type)
		if _, err := q.DeleteNotificationDestination(ctx, id); err != nil {
			return err
		}
		return nil
	})
}

// RotateSecret replaces the signing secret of a webhook destination and returns the new one once (audited:
// notification.destination_secret_rotated).
func (n *Notifications) RotateSecret(ctx context.Context, scope Scope, id uuid.UUID) (string, error) {
	var secret string
	spec := scopedSpec(scope, SpecNotificationRotateSecret, SpecPlatformNotificationRotateSecret)
	err := n.runner.RunTx(ctx, scope, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockNotificationDestination(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(destinationTarget(id, cur.Name))
		rec.SetParam("name", cur.Name)
		if cur.Type != string(outbound.TypeWebhook) {
			return problem.InvalidState.WithDetail("an e-mail destination has no signing secret")
		}
		plain, err := outbound.NewSecret()
		if err != nil {
			return err
		}
		ct, err := n.keys.Encrypt(ctx, NotificationWrapKey, scopeOrganization(ctx, scope), bao.FieldSecret, []byte(plain))
		if err != nil {
			return fmt.Errorf("encrypt the signing secret: %w", err)
		}
		if err := q.UpdateNotificationDestinationSecret(ctx, pgstore.UpdateNotificationDestinationSecretParams{
			ID: id, SecretCiphertext: &ct,
		}); err != nil {
			return err
		}
		secret = plain
		return nil
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// Test requests a test delivery (audited: notification.test_requested). Only the notifier can decrypt the URL and
// the secret, so it delivers the test in its next round and records notification.test_sent with the result (plan M9
// decision 17); the state's last test shows it.
func (n *Notifications) Test(ctx context.Context, scope Scope, id uuid.UUID) (uuid.UUID, error) {
	deliveryID := uuid.Must(uuid.NewV7())
	spec := scopedSpec(scope, SpecNotificationTest, SpecPlatformNotificationTest)
	spec.Params = map[string]any{"destination_id": id.String()}
	err := n.runner.RunTx(ctx, scope, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		cur, err := q.LockNotificationDestination(ctx, id)
		if err != nil {
			return notFound(err)
		}
		rec.SetTarget(destinationTarget(id, cur.Name))
		rec.SetParam("name", cur.Name)
		rec.SetParam("type", cur.Type)
		pending, err := q.PendingNotificationTestExists(ctx, id)
		if err != nil {
			return err
		}
		if pending {
			return problem.InvalidState.WithDetail("a test delivery of this destination is still pending; wait for its result")
		}
		requestedBy := actorDisplay(ctx)
		return foreignNotFound(q.InsertNotificationTestDelivery(ctx, pgstore.InsertNotificationTestDeliveryParams{
			ID: deliveryID, DestinationID: id, OrganizationID: scopeOrganization(ctx, scope), RequestedBy: &requestedBy,
		}))
	})
	if err != nil {
		return uuid.Nil, err
	}
	return deliveryID, nil
}

// ResolvePseudonym requests the user name behind a pseudonym of the organization's notifications (audited:
// notification.pseudonym_resolved, target the organization). The api never decrypts the pseudonym key: the notifier
// resolves the lookup in its next round (plan M9 decision 18). Organization scope only.
func (n *Notifications) ResolvePseudonym(ctx context.Context, id uuid.UUID, pseudonym string) (uuid.UUID, error) {
	lookupID := uuid.Must(uuid.NewV7())
	spec := SpecNotificationResolvePseudonym
	// A malformed value is never recorded: it may be anything the caller typed, including a real user name.
	if pseudonymPattern.MatchString(pseudonym) {
		spec.Params = map[string]any{"pseudonym": pseudonym}
	}
	err := n.runner.RunTx(ctx, ScopeOrg, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		org := scopeOrganization(ctx, ScopeOrg)
		rec.SetTarget(audit.Target{Type: "organization", ID: org.String()})
		if !pseudonymPattern.MatchString(pseudonym) {
			return problem.InvalidRequest.WithDetail("pseudonym must be u_ followed by 24 lowercase hexadecimal characters")
		}
		if _, err := q.GetNotificationDestination(ctx, id); err != nil {
			return notFound(err)
		}
		present, err := q.NotificationPseudonymKeyExists(ctx)
		if err != nil {
			return err
		}
		if !present {
			return problem.InvalidState.WithDetail("the organization has no pseudonym key: no destination pseudonymizes user names")
		}
		if err := q.LockNotificationPseudonymLookups(ctx, org); err != nil {
			return err
		}
		pending, err := q.PendingNotificationPseudonymLookupExists(ctx)
		if err != nil {
			return err
		}
		if pending {
			return problem.InvalidState.WithDetail("a pseudonym lookup of the organization is still pending; wait for its result")
		}
		return q.InsertNotificationPseudonymLookup(ctx, pgstore.InsertNotificationPseudonymLookupParams{
			ID: lookupID, OrganizationID: org, Pseudonym: pseudonym, RequestedBy: actorDisplay(ctx),
		})
	})
	if err != nil {
		return uuid.Nil, err
	}
	return lookupID, nil
}

// PseudonymLookup returns a pseudonym lookup (org_admin). A resolved lookup is deleted once it was read, so the user
// name is shown once; an unresolved one is answered with resolved false.
func (n *Notifications) PseudonymLookup(ctx context.Context, id, lookupID uuid.UUID) (PseudonymLookup, error) {
	var out PseudonymLookup
	if _, err := RequireOrg(ctx, RolesAdmin); err != nil {
		return out, err
	}
	err := n.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if _, err := q.GetNotificationDestination(ctx, id); err != nil {
			return notFound(err)
		}
		taken, err := q.TakeResolvedNotificationPseudonymLookup(ctx, lookupID)
		if err == nil {
			out.Pseudonym, out.Resolved, out.Username = taken.Pseudonym, true, taken.ResolvedUsername
			if out.Username == nil {
				none := ""
				out.Username = &none
			}
			return nil
		}
		if !db.IsNoRows(err) {
			return err
		}
		row, err := q.GetNotificationPseudonymLookup(ctx, lookupID)
		if err != nil {
			return notFound(err)
		}
		out.Pseudonym = row.Pseudonym
		return nil
	})
	return out, err
}

// validate checks a destination: type, custom codes against the registry, the remaining rules of plan M9 decision 9,
// the URL when checkURL is set, and the SMTP relay when requireEmail is set (creating or enabling an e-mail
// destination; disabling or renaming one works without a relay). Platform destinations never pseudonymize
// (decision 18).
func (n *Notifications) validate(ctx context.Context, scope Scope, in NotificationDestinationInput, checkURL, requireEmail bool) error {
	switch in.Type {
	case outbound.TypeWebhook:
		if checkURL && in.URL == nil {
			return problem.InvalidRequest.WithDetail("a webhook destination requires url")
		}
	case outbound.TypeEmail:
		if in.URL != nil {
			return problem.InvalidRequest.WithDetail("an e-mail destination has no url")
		}
		if requireEmail && !n.emailEnabled {
			return problem.EmailNotConfigured.WithDetail("this installation has no SMTP relay (PADDOCK_SMTP_ENABLED)")
		}
	default:
		return problem.InvalidRequest.WithDetail(outbound.ErrInvalidType.Error())
	}
	if scope == ScopePlatform && in.PseudonymizeUsers {
		return problem.InvalidRequest.WithDetail("platform events carry no user names: pseudonymize_users must be false")
	}
	if in.FilterMode == outbound.FilterCustom {
		for _, c := range in.Codes {
			if !audit.Code(c).Registered() {
				return problem.UnknownCode.WithDetail(fmt.Sprintf("%q is not a registered audit code", c))
			}
		}
	} else if len(in.Codes) > 0 {
		return problem.InvalidRequest.WithDetail("codes are only allowed with filter_mode custom")
	}
	d := outbound.Destination{
		Type: in.Type, Name: in.Name, FilterMode: in.FilterMode, Codes: auditCodes(in.Codes),
		HeartbeatIntervalS: in.HeartbeatIntervalS, Recipients: in.Recipients, EmailMinIntervalS: emailInterval(in),
	}
	var err error
	if checkURL && in.Type == outbound.TypeWebhook {
		d.URL = *in.URL
		err = n.urls.ValidateDestination(ctx, d)
	} else {
		err = outbound.ValidateSettings(d)
	}
	if err != nil {
		return problem.InvalidRequest.WithDetail(err.Error())
	}
	return nil
}

// ensurePseudonymKey creates the organization's pseudonym key unless it exists: a Transit data key wrapped under
// notification-pseudonym, which only the notifier unwraps.
func (n *Notifications) ensurePseudonymKey(ctx context.Context, q *pgstore.Queries, org uuid.UUID) error {
	present, err := q.NotificationPseudonymKeyExists(ctx)
	if err != nil || present {
		return err
	}
	ct, err := n.keys.WrappedDataKey(ctx, NotificationPseudonymKey, org, bao.FieldPseudonym)
	if err != nil {
		return fmt.Errorf("create the pseudonym key: %w", err)
	}
	return q.InsertNotificationPseudonymKey(ctx, pgstore.InsertNotificationPseudonymKeyParams{OrganizationID: org, KeyCiphertext: ct})
}

// startAtLatest asks the notifier to move the cursor to the newest event before the next delivery; the api never
// writes the cursor itself (migration 00085). false means the destination is not the scope's.
func (n *Notifications) startAtLatest(ctx context.Context, q *pgstore.Queries, scope Scope, id uuid.UUID) error {
	var started bool
	var err error
	if scope == ScopePlatform {
		started, err = q.StartPlatformNotificationDestinationAtLatest(ctx, id)
	} else {
		started, err = q.StartNotificationDestinationAtLatest(ctx, id)
	}
	if err != nil {
		return err
	}
	if !started {
		return problem.NotFound
	}
	return nil
}

func (n *Notifications) read(ctx context.Context, scope Scope, fn func(ctx context.Context, q *pgstore.Queries) error) error {
	if scope == ScopePlatform {
		return n.platform.InPlatform(ctx, fn)
	}
	return n.org.InOrg(ctx, fn)
}

func (n *Notifications) destination(r pgstore.GetNotificationDestinationRow) NotificationDestination {
	out := NotificationDestination{
		ID: r.ID, Type: r.Type, Name: r.Name, Enabled: r.Enabled, FilterMode: r.FilterMode, Codes: nonNil(r.Codes),
		PseudonymizeUsers: r.PseudonymizeUsers, IncludeParams: r.IncludeParams, URLDisplay: r.UrlDisplay,
		HeartbeatIntervalS: int(r.HeartbeatIntervalS), Recipients: nonNil(r.Recipients),
		EmailMinIntervalS: int(r.EmailMinIntervalS), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		State: NotificationDestinationState{Status: "active"},
	}
	s := &out.State
	if r.Status != nil {
		s.Status = *r.Status
	}
	if r.CursorCommitSeq != nil {
		s.CursorCommitSeq = *r.CursorCommitSeq
	}
	if r.ForwardSeq != nil {
		s.ForwardSeq = *r.ForwardSeq
	}
	s.LastSuccessAt, s.LastAttemptAt, s.NextAttemptAt, s.StalledSince = r.LastSuccessAt, r.LastAttemptAt, r.NextAttemptAt, r.StalledSince
	s.LastError = r.LastError
	if r.FirstFailureAt != nil {
		s.LagSeconds = max(0, int64(n.now().Sub(*r.FirstFailureAt)/time.Second))
	}
	if r.LastTestAt != nil {
		s.LastTest = &NotificationTestResult{At: *r.LastTestAt, OK: r.LastTestOk != nil && *r.LastTestOk, Error: r.LastTestError}
	}
	return out
}

// requireNotificationRead checks a read: auditors see the configuration, never a secret (plan M9 decision 14).
func requireNotificationRead(ctx context.Context, scope Scope) error {
	if scope == ScopePlatform {
		_, err := RequirePlatform(ctx)
		return err
	}
	_, err := RequireOrg(ctx, RolesAudit)
	return err
}

func scopedSpec(scope Scope, org, platform ActionSpec) ActionSpec {
	if scope == ScopePlatform {
		return platform
	}
	return org
}

// scopeOrganization is the organization of the rows a use case writes: the caller's, or the nil organization of the
// platform scope.
func scopeOrganization(ctx context.Context, scope Scope) uuid.UUID {
	if scope == ScopePlatform {
		return audit.PlatformOrganizationID
	}
	p, _ := principal.From(ctx)
	return p.OrganizationID
}

// actorDisplay names the administrator in created_by and requested_by.
func actorDisplay(ctx context.Context) string {
	p, _ := principal.From(ctx)
	if p.Display != "" {
		return p.Display
	}
	return p.ID.String()
}

// withDestinationParams puts the requested settings into the event params, so a denied or refused attempt shows what
// was asked for; url_display never contains a path or query, which may carry the credential.
func withDestinationParams(spec ActionSpec, in NotificationDestinationInput) ActionSpec {
	spec.Params = map[string]any{
		"name": in.Name, "type": string(in.Type), "filter_mode": string(in.FilterMode), "codes_count": len(in.Codes),
		"pseudonymize_users": in.PseudonymizeUsers, "include_params": in.IncludeParams,
		"heartbeat_interval_s": in.HeartbeatIntervalS, "email_min_interval_s": emailInterval(in), "enabled": in.Enabled,
	}
	switch in.Type {
	case outbound.TypeWebhook:
		if in.URL != nil {
			spec.Params["url_display"] = outbound.DisplayURL(*in.URL)
		}
	case outbound.TypeEmail:
		spec.Params["recipient_count"] = len(in.Recipients)
	}
	return spec
}

func destinationTarget(id uuid.UUID, name string) audit.Target {
	return audit.Target{Type: "notification_destination", ID: id.String(), Display: name}
}

// emailInterval is the e-mail interval to store: the column default for a webhook, which has none.
func emailInterval(in NotificationDestinationInput) int {
	if in.Type != outbound.TypeEmail && in.EmailMinIntervalS == 0 {
		return defaultEmailMinIntervalS
	}
	return in.EmailMinIntervalS
}

// defaultEmailMinIntervalS is the column default of notification_destination.email_min_interval_s.
const defaultEmailMinIntervalS = 300

// customCodes are the stored codes: the custom list, none for the other modes.
func customCodes(in NotificationDestinationInput) []string {
	if in.FilterMode != outbound.FilterCustom {
		return []string{}
	}
	return nonNil(in.Codes)
}

func auditCodes(codes []string) []audit.Code {
	out := make([]audit.Code, len(codes))
	for i, c := range codes {
		out[i] = audit.Code(c)
	}
	return out
}

// changedFields lists the fields an update changed, sorted; url whenever a new URL was given (the stored one cannot
// be compared).
func changedFields(cur pgstore.GetNotificationDestinationRow, in NotificationDestinationInput) []string {
	var out []string
	add := func(field string, changed bool) {
		if changed {
			out = append(out, field)
		}
	}
	add("name", cur.Name != in.Name)
	add("enabled", cur.Enabled != in.Enabled)
	add("filter_mode", cur.FilterMode != string(in.FilterMode))
	add("codes", !slices.Equal(nonNil(cur.Codes), customCodes(in)))
	add("pseudonymize_users", cur.PseudonymizeUsers != in.PseudonymizeUsers)
	add("include_params", cur.IncludeParams != in.IncludeParams)
	add("url", in.URL != nil)
	add("heartbeat_interval_s", int(cur.HeartbeatIntervalS) != in.HeartbeatIntervalS)
	add("recipients", !slices.Equal(nonNil(cur.Recipients), nonNil(in.Recipients)))
	add("email_min_interval_s", int(cur.EmailMinIntervalS) != emailInterval(in))
	slices.Sort(out)
	return nonNil(out)
}

// foreignNotFound maps a foreign key violation on a destination reference to not_found: since migration 00085 every
// child references (destination_id, organization_id), so a destination of another organization fails exactly like a
// missing one and the answer reveals nothing about it.
func foreignNotFound(err error) error {
	if db.IsForeignKeyViolation(err) {
		return problem.NotFound
	}
	return err
}
