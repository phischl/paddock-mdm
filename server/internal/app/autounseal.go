package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// SealStatusReader reads OpenBao's seal status without a token (bao.Client).
type SealStatusReader interface {
	SealStatus(ctx context.Context) (bao.SealStatus, error)
}

// unsealerActor is the actor of every automatic unseal.
var unsealerActor = audit.Actor{Type: audit.ActorSystem, Display: "paddock-unsealer"}

// Privileged actions of the automatic unseal (ADR 0035 decision 2).
var (
	SpecAutoUnsealEnable     = ActionSpec{Code: audit.CodePlatformAutoUnsealEnabled, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	SpecAutoUnsealDisable    = ActionSpec{Code: audit.CodePlatformAutoUnsealDisabled, AllowedRoles: RolesPlatform, RequiresStepUp: true}
	specAutoUnsealDisableCLI = ActionSpec{Code: audit.CodePlatformAutoUnsealDisabled, Actor: &adminActor}
	// SpecAutoUnsealObserved is recorded by the worker for the unsealer's report (plan M8u decision 13); exported
	// because the worker records it.
	SpecAutoUnsealObserved = ActionSpec{Code: audit.CodePlatformOpenBaoAutoUnsealed, Actor: &unsealerActor}
)

// ErrAutoUnsealFailed is the error code of a failed automatic unseal the worker records; never sent over HTTP.
var ErrAutoUnsealFailed = &problem.Error{Code: "auto_unseal_failed", Status: http.StatusInternalServerError}

// AutoUnseal are the platform use cases of the automatic unseal.
type AutoUnseal struct {
	runner   *ActionRunner
	platform *db.PlatformPool
	seal     SealStatusReader // nil: seal status reported as unreachable
}

// NewAutoUnseal creates the use cases.
func NewAutoUnseal(runner *ActionRunner, platform *db.PlatformPool, seal SealStatusReader) *AutoUnseal {
	return &AutoUnseal{runner: runner, platform: platform, seal: seal}
}

// AutoUnsealStatus is the setting, the report and the seal status the portal shows.
type AutoUnsealStatus struct {
	Setting autounseal.Setting
	Seal    bao.SealStatus // Reachable false when OpenBao did not answer
}

// AutoUnsealSetting maps the row openbao_auto_unseal.
func AutoUnsealSetting(r pgstore.OpenbaoAutoUnseal) autounseal.Setting {
	return autounseal.Setting{
		State:                 autounseal.State(r.State),
		DisclaimerVersion:     deref(r.DisclaimerVersion, ""),
		Acknowledgement:       deref(r.Acknowledgement, ""),
		AcknowledgedBy:        deref(r.AcknowledgedBy, ""),
		AcknowledgedBySubject: deref(r.AcknowledgedBySubject, ""),
		AcknowledgedAt:        deref(r.AcknowledgedAt, time.Time{}),
		DisabledBy:            deref(r.DisabledBy, ""),
		DisabledAt:            deref(r.DisabledAt, time.Time{}),
		Report: autounseal.Report{
			SeenAt:            deref(r.UnsealerSeenAt, time.Time{}),
			SharesPresent:     r.UnsealerSharesPresent,
			UnsealCount:       r.UnsealCount,
			LastUnsealAt:      deref(r.LastUnsealAt, time.Time{}),
			FailureCount:      r.FailureCount,
			LastFailureAt:     deref(r.LastFailureAt, time.Time{}),
			LastFailureReason: deref(r.LastFailureReason, ""),
		},
	}
}

// Status reads the setting with the platform role and the seal status; platform administrators only (ErrForbidden
// for others, no audit event: a read).
func (a *AutoUnseal) Status(ctx context.Context) (AutoUnsealStatus, error) {
	if _, err := RequirePlatform(ctx); err != nil {
		return AutoUnsealStatus{}, err
	}
	var out AutoUnsealStatus
	err := a.platform.InPlatform(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		row, err := q.GetAutoUnseal(ctx)
		if err != nil {
			return fmt.Errorf("read automatic unseal: %w", err)
		}
		out.Setting = AutoUnsealSetting(row)
		return nil
	})
	if err != nil {
		return out, err
	}
	out.Seal = a.sealStatus(ctx)
	return out, nil
}

func (a *AutoUnseal) sealStatus(ctx context.Context) bao.SealStatus {
	if a.seal == nil {
		return bao.SealStatus{}
	}
	st, err := a.seal.SealStatus(ctx)
	if err != nil {
		return bao.SealStatus{}
	}
	return st
}

// Enable records the acknowledgement and sets the state to enabled (audited platform.auto_unseal_enabled with
// disclaimer_version, acknowledgement and previous_state). Validation errors: problem.DisclaimerOutdated (409) and
// problem.InvalidRequest with detail "acknowledgement does not match the disclaimer" (400); both are recorded as
// failure.
func (a *AutoUnseal) Enable(ctx context.Context, disclaimerVersion, acknowledgement string) (AutoUnsealStatus, error) {
	var out AutoUnsealStatus
	err := a.runner.RunTx(ctx, ScopePlatform, SpecAutoUnsealEnable, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		row, err := q.GetAutoUnsealForUpdate(ctx)
		if err != nil {
			return fmt.Errorf("read automatic unseal: %w", err)
		}
		rec.SetParam("disclaimer_version", disclaimerVersion)
		rec.SetParam("acknowledgement", acknowledgement)
		rec.SetParam("previous_state", row.State)
		switch err := autounseal.ValidateAcknowledgement(disclaimerVersion, acknowledgement); {
		case errors.Is(err, autounseal.ErrDisclaimerOutdated):
			return problem.DisclaimerOutdated
		case err != nil:
			return problem.InvalidRequest.WithDetail("acknowledgement does not match the disclaimer")
		}
		if err := q.EnableAutoUnseal(ctx, pgstore.EnableAutoUnsealParams{
			DisclaimerVersion: &disclaimerVersion, Acknowledgement: &acknowledgement,
			AcknowledgedBy: &p.Display, AcknowledgedBySubject: &p.Subject,
		}); err != nil {
			return fmt.Errorf("enable automatic unseal: %w", err)
		}
		return readSetting(ctx, q, &out.Setting)
	})
	if err != nil {
		return out, err
	}
	out.Seal = a.sealStatus(ctx)
	return out, nil
}

// Disable sets the state to disabled (audited platform.auto_unseal_disabled, method portal).
func (a *AutoUnseal) Disable(ctx context.Context) (AutoUnsealStatus, error) {
	spec := SpecAutoUnsealDisable
	spec.Params = map[string]any{"method": "portal"}
	setting, err := a.disable(ctx, spec)
	if err != nil {
		return AutoUnsealStatus{}, err
	}
	return AutoUnsealStatus{Setting: setting, Seal: a.sealStatus(ctx)}, nil
}

// DisableCLI is Disable for paddock-server admin auto-unseal disable (method cli, system principal).
func (a *AutoUnseal) DisableCLI(ctx context.Context) (autounseal.Setting, error) {
	spec := specAutoUnsealDisableCLI
	spec.Params = map[string]any{"method": "cli"}
	return a.disable(systemPlatform(ctx), spec)
}

func (a *AutoUnseal) disable(ctx context.Context, spec ActionSpec) (autounseal.Setting, error) {
	var out autounseal.Setting
	err := a.runner.RunTx(ctx, ScopePlatform, spec, func(ctx context.Context, q *pgstore.Queries, rec Recorder) error {
		p, _ := principal.From(ctx)
		row, err := q.GetAutoUnsealForUpdate(ctx)
		if err != nil {
			return fmt.Errorf("read automatic unseal: %w", err)
		}
		rec.SetParam("previous_state", row.State)
		if err := q.DisableAutoUnseal(ctx, &p.Display); err != nil {
			return fmt.Errorf("disable automatic unseal: %w", err)
		}
		return readSetting(ctx, q, &out)
	})
	return out, err
}

func readSetting(ctx context.Context, q *pgstore.Queries, out *autounseal.Setting) error {
	row, err := q.GetAutoUnseal(ctx)
	if err != nil {
		return fmt.Errorf("read automatic unseal: %w", err)
	}
	*out = AutoUnsealSetting(row)
	return nil
}

// Load reads the setting with a system principal (CLI show and verify).
func (a *AutoUnseal) Load(ctx context.Context) (autounseal.Setting, error) {
	var out autounseal.Setting
	err := a.platform.InPlatform(systemPlatform(ctx), func(ctx context.Context, q *pgstore.Queries) error {
		return readSetting(ctx, q, &out)
	})
	return out, err
}
