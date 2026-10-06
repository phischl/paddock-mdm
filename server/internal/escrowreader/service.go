package escrowreader

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// ProofVerifier checks a step-up ID token (stepupproof.Verifier); refusals wrap stepupproof.ErrInvalid.
type ProofVerifier interface {
	Verify(ctx context.Context, raw string) (stepupproof.Claims, error)
}

// UseCounter counts the decryptions of a step-up token until it expires (stepupproof.Store).
type UseCounter interface {
	Use(ctx context.Context, jti string, until time.Time) (int64, error)
}

// Decrypter decrypts with escrow-wrap (Reader).
type Decrypter interface {
	Decrypt(ctx context.Context, version int, ciphertext string) ([]byte, error)
}

// purposeKinds is the escrow kind each purpose may decrypt.
var purposeKinds = map[string]string{
	app.PurposeLocalAdminReveal: escrow.KindAdminPassword,
	app.PurposeDiskRecoveryKey:  escrow.KindLUKSRecoveryKey,
	app.PurposeDiskHeader:       escrow.KindLUKSHeader,
}

// Service is the escrow-reader's HTTP service.
type Service struct {
	secret    []byte
	org       *db.OrgPool // role paddock_escrow_reader
	proofs    ProofVerifier
	uses      UseCounter
	decrypter Decrypter
}

// NewService creates the service; secret is the bearer secret shared with the api.
func NewService(secret string, org *db.OrgPool, proofs ProofVerifier, uses UseCounter, decrypter Decrypter) *Service {
	return &Service{secret: []byte(secret), org: org, proofs: proofs, uses: uses, decrypter: decrypter}
}

// Handler serves POST /internal/v1/decrypt.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+DecryptPath, s.decrypt)
	return mux
}

// errRefused carries a refusal code; it is answered with 403.
type errRefused struct{ code, reason string }

func (e errRefused) Error() string { return e.code + ": " + e.reason }

// decrypt checks, in this order, the bearer secret, the request, the step-up token, that its subject is an
// administrator of the organization, that every escrow belongs to the device, the organization and the purpose, and
// the token's use count; then it decrypts. It never logs a token or a plaintext.
func (s *Service) decrypt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(auth), s.secret) != 1 {
		slog.WarnContext(ctx, "escrow decryption without valid bearer secret", "remote", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req decryptRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.OrganizationID == uuid.Nil || req.DeviceID == uuid.Nil ||
		len(req.EscrowIDs) == 0 || len(req.EscrowIDs) > maxEscrows || req.StepUpIDToken == "" || purposeKinds[req.Purpose] == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	plain, err := s.open(ctx, req)
	var refused errRefused
	switch {
	case errors.As(err, &refused):
		slog.WarnContext(ctx, "escrow decryption refused", "code", refused.code, "reason", refused.reason,
			"organization_id", req.OrganizationID, "device_id", req.DeviceID, "purpose", req.Purpose)
		s.write(w, http.StatusForbidden, refusal{Code: refused.code})
		return
	case err != nil:
		slog.ErrorContext(ctx, "escrow decryption failed", "organization_id", req.OrganizationID, "device_id", req.DeviceID,
			"purpose", req.Purpose, "error", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() {
		for _, b := range plain {
			clear(b)
		}
	}()
	slog.InfoContext(ctx, "escrows decrypted", "organization_id", req.OrganizationID, "device_id", req.DeviceID,
		"purpose", req.Purpose, "escrows", len(plain))
	s.write(w, http.StatusOK, decryptResponse{Plaintexts: plain})
}

// open runs the checks and decrypts; a failed check is an errRefused.
func (s *Service) open(ctx context.Context, req decryptRequest) (map[uuid.UUID][]byte, error) {
	claims, err := s.proofs.Verify(ctx, req.StepUpIDToken)
	if errors.Is(err, stepupproof.ErrInvalid) {
		return nil, errRefused{refusedStepUp, err.Error()}
	}
	if err != nil {
		return nil, err
	}
	var rows []pgstore.EscrowSecret
	// The organization comes from the request; every row is checked against it and the device below.
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, OrganizationID: req.OrganizationID})
	err = s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		admin, err := q.GetAdminAccountBySubject(ctx, claims.Subject)
		if db.IsNoRows(err) || err == nil && (admin.OrganizationID != req.OrganizationID || admin.Role != string(principal.RoleOrgAdmin)) {
			return errRefused{refusedAdmin, "the step-up subject is no administrator of the organization"}
		}
		if err != nil {
			return err
		}
		if _, err := q.GetDevice(ctx, req.DeviceID); db.IsNoRows(err) {
			return errRefused{refusedEscrow, "the device is not in the organization"}
		} else if err != nil {
			return err
		}
		rows, err = q.GetEscrowSecrets(ctx, req.EscrowIDs)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := checkRows(rows, req); err != nil {
		return nil, err
	}
	n, err := s.uses.Use(ctx, claims.JTI, claims.Expiry)
	if err != nil {
		return nil, fmt.Errorf("count the use of the step-up token: %w", err)
	}
	if n > stepupproof.MaxUses {
		return nil, errRefused{refusedExhausted, fmt.Sprintf("the step-up token was used %d times", n)}
	}
	plain := make(map[uuid.UUID][]byte, len(rows))
	for _, row := range rows {
		ct := row.Ciphertext
		if row.Kind == escrow.KindLUKSHeader {
			ct = row.WrappedDek // the header's key; the api opens the sealed object with it
		}
		b, err := s.decrypter.Decrypt(ctx, int(row.KeyVersion), base64.StdEncoding.EncodeToString(ct))
		if err != nil {
			for _, p := range plain {
				clear(p)
			}
			return nil, fmt.Errorf("decrypt escrow %s: %w", row.ID, err)
		}
		plain[row.ID] = b
	}
	return plain, nil
}

// checkRows requires exactly the requested escrows, each of the device, the organization and the purpose's kind.
func checkRows(rows []pgstore.EscrowSecret, req decryptRequest) error {
	requested := map[uuid.UUID]bool{}
	for _, id := range req.EscrowIDs {
		requested[id] = true
	}
	if len(rows) != len(requested) {
		return errRefused{refusedEscrow, fmt.Sprintf("%d of %d escrows found in the organization", len(rows), len(requested))}
	}
	for _, row := range rows {
		if row.DeviceID != req.DeviceID || row.OrganizationID != req.OrganizationID || row.Kind != purposeKinds[req.Purpose] {
			return errRefused{refusedEscrow, fmt.Sprintf("escrow %s is not of the device or not of kind %s", row.ID, purposeKinds[req.Purpose])}
		}
	}
	return nil
}

// write answers v as JSON with the MAC of the body.
func (s *Service) write(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(macHeader, mac(s.secret, body))
	w.WriteHeader(status)
	_, _ = w.Write(body)
	clear(body)
}
