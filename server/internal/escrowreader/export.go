package escrowreader

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/recoveryexport"
	"github.com/phischl/paddock-mdm/server/internal/stepupproof"
)

// ExportPath is the escrow-reader's endpoint of the encrypted recovery export (plan M17 amendment b decision 24).
const ExportPath = "/internal/v1/recovery-export"

// The export's answer: its counts and the MAC of the request's nonce and the counts in headers, before the first byte,
// so the api opens the download only for a holder of the shared secret; the MAC of the body in a trailer, which the
// api checks before it releases the end of the message.
const (
	devicesHeader = "X-Paddock-Export-Devices"
	secretsHeader = "X-Paddock-Export-Secrets"
	bodyMacHeader = "X-Paddock-Escrow-Reader-Body-Mac"
)

// exportDisposition marks the export as a download under a fixed name: the api names the requester's file itself, and
// no value of the request reaches a header a browser would interpret.
const exportDisposition = `attachment; filename="paddock-recovery-export.asc"`

// refusedState: the organization's deletion is not pending.
const refusedState = "not_pending"

// exportRequest is the body of POST /internal/v1/recovery-export.
type exportRequest struct {
	OrganizationID     uuid.UUID `json:"organization_id"`
	Slug               string    `json:"slug"`
	ExportedAt         time.Time `json:"exported_at"`
	Scope              string    `json:"scope"`
	StepUpIDToken      string    `json:"stepup_id_token"`
	LocalAdminUsername string    `json:"local_admin_username"`
	Recipient          string    `json:"recipient"`
	PublicKey          string    `json:"public_key,omitempty"`
	Passphrase         string    `json:"passphrase,omitempty"`
	Nonce              string    `json:"nonce"`
}

func headerMAC(secret []byte, nonce string, devices, secrets int) string {
	return mac(secret, []byte("recovery-export\n"+nonce+"\n"+strconv.Itoa(devices)+"\n"+strconv.Itoa(secrets)))
}

// DecryptBatch returns the plaintexts of ciphertexts wrapped with escrow-wrap, in order. The caller zeroes them.
func (r *Reader) DecryptBatch(ctx context.Context, items []bao.VersionedCiphertext) ([][]byte, error) {
	return r.c.DecryptBatch(ctx, escrow.KeyName, items)
}

// exportDevice is one device line before decryption; escrows indexes the rows of its secrets.
type exportDevice struct {
	id       uuid.UUID
	hostname string
	volumes  []exportVolume
	admin    int // row of the admin password, -1 without
}

type exportVolume struct {
	uuid string
	row  int
}

func (d exportDevice) secrets() int {
	n := len(d.volumes)
	if d.admin >= 0 {
		n++
	}
	return n
}

// groupDevices turns the rows (ordered by device) into device lines.
func groupDevices(rows []pgstore.ListRecoveryExportEscrowsRow) ([]exportDevice, int) {
	var out []exportDevice
	secrets := 0
	for i, row := range rows {
		if len(out) == 0 || out[len(out)-1].id != row.DeviceID {
			out = append(out, exportDevice{id: row.DeviceID, hostname: row.Hostname, admin: -1})
		}
		d := &out[len(out)-1]
		switch row.Kind {
		case escrow.KindAdminPassword:
			d.admin = i
		case escrow.KindLUKSRecoveryKey:
			v := ""
			if row.Volume.Valid {
				v = row.Volume.UUID.String()
			}
			d.volumes = append(d.volumes, exportVolume{uuid: v, row: i})
		default:
			continue
		}
		secrets++
	}
	return out, secrets
}

// export streams the encrypted recovery export. It checks, in this order, the bearer secret, the request and its
// recipient, the step-up token, that its subject is an administrator of the organization (scope organization) or a
// platform administrator by the token's signed groups (scope platform), that the organization's deletion is pending,
// and the token's use count (one use per export); then it decrypts in Transit batches of at most bao.MaxBatch and
// encrypts every batch into the message as it streams. Each batch's plaintexts and lines are zeroed after writing, as a
// best effort (the OpenBao client and go-crypto keep copies in memory until garbage collection, see package
// recoveryexport); no plaintext, token or passphrase is written anywhere else or logged. A failure after the first byte cuts the
// response off, so the client holds a message OpenPGP rejects.
func (s *Service) export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(auth), s.secret) != 1 {
		slog.WarnContext(ctx, "recovery export without valid bearer secret", "remote", r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req exportRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.OrganizationID == uuid.Nil || req.Slug == "" || req.ExportedAt.IsZero() ||
		(req.Scope != app.RequesterOrganization && req.Scope != app.RequesterPlatform) || req.StepUpIDToken == "" ||
		req.Nonce == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	recipient, err := recoveryexport.ParseRecipient(req.Recipient, req.PublicKey, req.Passphrase)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer recipient.Clear()
	rows, err := s.exportRows(ctx, req)
	var refused errRefused
	switch {
	case errors.As(err, &refused):
		slog.WarnContext(ctx, "recovery export refused", "code", refused.code, "reason", refused.reason,
			"organization_id", req.OrganizationID, "scope", req.Scope)
		s.write(w, http.StatusForbidden, refusal{Code: refused.code})
		return
	case err != nil:
		slog.ErrorContext(ctx, "recovery export failed", "organization_id", req.OrganizationID, "error", err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	devices, secrets := groupDevices(rows)
	h := w.Header()
	h.Set("Content-Type", recoveryexport.ContentType)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", exportDisposition)
	h.Set("Trailer", bodyMacHeader)
	h.Set(devicesHeader, strconv.Itoa(len(devices)))
	h.Set(secretsHeader, strconv.Itoa(secrets))
	h.Set(macHeader, headerMAC(s.secret, req.Nonce, len(devices), secrets))
	rc := http.NewResponseController(w)
	// The server's write timeout (120 s) would cut a large organization's export off; the stream gets the client's
	// whole export budget instead. A writer without deadline support (HTTP/2, tests) has no timeout to extend.
	_ = rc.SetWriteDeadline(time.Now().Add(exportTimeout))
	w.WriteHeader(http.StatusOK)
	body := hmac.New(sha256.New, s.secret)
	if err := s.stream(ctx, io.MultiWriter(w, body), rc, req, recipient, rows, devices); err != nil {
		slog.ErrorContext(ctx, "recovery export broke off while streaming", "organization_id", req.OrganizationID, "error", err)
		panic(http.ErrAbortHandler)
	}
	h.Set(bodyMacHeader, base64.StdEncoding.EncodeToString(body.Sum(nil)))
	slog.InfoContext(ctx, "recovery export streamed", "organization_id", req.OrganizationID, "scope", req.Scope,
		"devices", len(devices), "secrets", secrets)
}

// exportRows runs the checks before the first byte and returns the escrows to decrypt.
func (s *Service) exportRows(ctx context.Context, req exportRequest) ([]pgstore.ListRecoveryExportEscrowsRow, error) {
	claims, err := s.proofs.Verify(ctx, req.StepUpIDToken)
	if errors.Is(err, stepupproof.ErrInvalid) {
		return nil, errRefused{refusedStepUp, err.Error()}
	}
	if err != nil {
		return nil, err
	}
	if req.Scope == app.RequesterPlatform {
		if res, ok := organization.ResolveRole(claims.Groups).Active(organization.ChoicePlatform); !ok || !res.Platform {
			return nil, errRefused{refusedAdmin, "the step-up subject is no platform administrator"}
		}
	}
	var rows []pgstore.ListRecoveryExportEscrowsRow
	// The organization comes from the request; the escrow-reader checks its pending deletion itself.
	ctx = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, OrganizationID: req.OrganizationID})
	err = s.org.InOrg(ctx, func(ctx context.Context, q *pgstore.Queries) error {
		if req.Scope == app.RequesterOrganization {
			admin, err := q.GetAdminAccountBySubject(ctx, claims.Subject)
			if db.IsNoRows(err) || err == nil && (admin.OrganizationID != req.OrganizationID ||
				principal.Role(admin.Role) != principal.RoleOrgAdmin || admin.DisabledAt != nil) {
				return errRefused{refusedAdmin, "the step-up subject is no administrator of the organization"}
			}
			if err != nil {
				return err
			}
		}
		open, err := q.RecoveryExportOpen(ctx, pgstore.RecoveryExportOpenParams{ID: req.OrganizationID,
			CutoffSeconds: app.RecoveryExportCutoff.Seconds()})
		if err != nil {
			return err
		}
		if !open {
			return errRefused{refusedState, "no deletion of the organization is pending, or its export closed"}
		}
		rows, err = q.ListRecoveryExportEscrows(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	n, err := s.uses.Use(ctx, claims.JTI, claims.Expiry)
	if err != nil {
		return nil, fmt.Errorf("count the use of the step-up token: %w", err)
	}
	if n > stepupproof.MaxUses {
		return nil, errRefused{refusedExhausted, fmt.Sprintf("the step-up token was used %d times", n)}
	}
	return rows, nil
}

// stream writes the message: the header line, then the device lines batch by batch.
func (s *Service) stream(ctx context.Context, dst io.Writer, rc *http.ResponseController, req exportRequest,
	recipient recoveryexport.Recipient, rows []pgstore.ListRecoveryExportEscrowsRow, devices []exportDevice) error {
	msg, err := recoveryexport.Encrypt(dst, recipient)
	if err != nil {
		return err
	}
	line, err := recoveryexport.AppendHeader(nil, recoveryexport.NewHeader(req.OrganizationID, req.Slug, req.ExportedAt, len(devices)))
	if err != nil {
		return err
	}
	if _, err := msg.Write(line); err != nil {
		return err
	}
	// The download starts before the first decryption; the client sees progress per batch from then on. A writer
	// without flush support (tests) buffers instead.
	_ = rc.Flush()
	for start := 0; start < len(devices); {
		end, n := start, 0
		for end < len(devices) && (end == start || n+devices[end].secrets() <= bao.MaxBatch) {
			n += devices[end].secrets()
			end++
		}
		if err := s.writeBatch(ctx, msg, rows, devices[start:end], req.LocalAdminUsername); err != nil {
			return err
		}
		_ = rc.Flush()
		start = end
	}
	return msg.Close()
}

// writeBatch decrypts the secrets of batch in one Transit call and writes their lines; plaintexts and lines are zeroed
// afterwards, also on an error.
func (s *Service) writeBatch(ctx context.Context, msg io.Writer, rows []pgstore.ListRecoveryExportEscrowsRow,
	batch []exportDevice, username string) error {
	var items []bao.VersionedCiphertext
	for _, d := range batch {
		for _, v := range d.volumes {
			items = append(items, wrappedOf(rows[v.row]))
		}
		if d.admin >= 0 {
			items = append(items, wrappedOf(rows[d.admin]))
		}
	}
	var plain [][]byte
	if len(items) > 0 {
		var err error
		if plain, err = s.decrypter.DecryptBatch(ctx, items); err != nil {
			return fmt.Errorf("decrypt a batch of %d escrows: %w", len(items), err)
		}
		if len(plain) != len(items) {
			for _, p := range plain {
				clear(p)
			}
			return fmt.Errorf("decrypt a batch: %d plaintexts for %d escrows", len(plain), len(items))
		}
	}
	defer func() {
		for _, p := range plain {
			clear(p)
		}
	}()
	next := 0
	for _, d := range batch {
		line := recoveryexport.Device{ID: d.id, Hostname: d.hostname, Volumes: make([]recoveryexport.Volume, 0, len(d.volumes))}
		for _, v := range d.volumes {
			line.Volumes = append(line.Volumes, recoveryexport.Volume{UUID: v.uuid, RecoveryKey: plain[next]})
			next++
		}
		if d.admin >= 0 {
			line.LocalAdmin = &recoveryexport.LocalAdmin{Username: username, Password: plain[next]}
			next++
		}
		// Allocated at its bound, the line never grows, so this buffer leaves no copy of a secret behind unzeroed.
		buf := recoveryexport.AppendDevice(make([]byte, 0, recoveryexport.DeviceLineBound(line)), line)
		_, err := msg.Write(buf)
		clear(buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func wrappedOf(row pgstore.ListRecoveryExportEscrowsRow) bao.VersionedCiphertext {
	return bao.VersionedCiphertext{Version: int(row.KeyVersion), Ciphertext: base64.StdEncoding.EncodeToString(row.Ciphertext)}
}

// Export implements app.RecoveryExporter: it sends the request with a fresh nonce, checks the MAC of the answer's
// headers before it calls open, and copies the message into open's writer while it computes the body's MAC. The
// last bytes, which end the armour, are held back: release writes them, which the caller does only after the
// trailer's MAC matched and the export's audit event was recorded, so neither an answer of anyone else nor an
// unaudited export becomes a complete message.
func (c *Client) Export(ctx context.Context, call app.RecoveryExportCall, open func(app.RecoveryExportCounts) io.Writer) (
	app.RecoveryExportCounts, func() error, error,
) {
	var counts app.RecoveryExportCounts
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return counts, nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	body, err := json.Marshal(exportRequest{OrganizationID: call.OrganizationID, Slug: call.Slug, ExportedAt: call.ExportedAt,
		Scope: call.Scope, StepUpIDToken: call.StepUpIDToken, LocalAdminUsername: call.LocalAdminUsername,
		Recipient: call.Recipient, PublicKey: call.PublicKey, Passphrase: call.Passphrase, Nonce: nonce})
	if err != nil {
		return counts, nil, err
	}
	defer clear(body)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+ExportPath, bytes.NewReader(body))
	if err != nil {
		return counts, nil, err
	}
	hr.Header.Set("Authorization", "Bearer "+string(c.secret))
	hr.Header.Set("Content-Type", "application/json")
	resp, err := c.stream.Do(hr)
	if err != nil {
		return counts, nil, fmt.Errorf("escrow reader: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return counts, nil, fmt.Errorf("escrow reader: %w", err)
		}
		if !hmac.Equal([]byte(resp.Header.Get(macHeader)), []byte(mac(c.secret, data))) {
			return counts, nil, errors.New("escrow reader: refusal without valid MAC")
		}
		var r refusal
		_ = json.Unmarshal(data, &r)
		if r.Code == refusedState {
			return counts, nil, fmt.Errorf("%w: %s", app.ErrEscrowNotPending, r.Code)
		}
		return counts, nil, fmt.Errorf("%w: %s", app.ErrEscrowRefused, r.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return counts, nil, fmt.Errorf("escrow reader: HTTP %d", resp.StatusCode)
	}
	counts.Devices, err = strconv.Atoi(resp.Header.Get(devicesHeader))
	if err == nil {
		counts.Secrets, err = strconv.Atoi(resp.Header.Get(secretsHeader))
	}
	if err != nil || !hmac.Equal([]byte(resp.Header.Get(macHeader)), []byte(headerMAC(c.secret, nonce, counts.Devices, counts.Secrets))) {
		return app.RecoveryExportCounts{}, nil, errors.New("escrow reader: export answer without valid MAC")
	}
	dst := &holdback{w: open(counts), keep: holdbackBytes}
	sum := hmac.New(sha256.New, c.secret)
	if _, err := io.Copy(dst, io.TeeReader(resp.Body, sum)); err != nil {
		return counts, nil, fmt.Errorf("escrow reader: the export broke off: %w", err)
	}
	if !macMatches(sum, resp.Trailer.Get(bodyMacHeader)) {
		return counts, nil, errors.New("escrow reader: export body without valid MAC")
	}
	return counts, dst.release, nil
}

func macMatches(sum hash.Hash, got string) bool {
	return got != "" && hmac.Equal([]byte(got), []byte(base64.StdEncoding.EncodeToString(sum.Sum(nil))))
}

// holdbackBytes is more than the armour's checksum and end line, so a held-back message is never complete.
const holdbackBytes = 1024

// holdback writes everything but its last keep bytes; release writes those.
type holdback struct {
	w    io.Writer
	keep int
	buf  []byte
}

func (h *holdback) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	if over := len(h.buf) - h.keep; over > 0 {
		if _, err := h.w.Write(h.buf[:over]); err != nil {
			return 0, err
		}
		h.buf = h.buf[:copy(h.buf, h.buf[over:])]
	}
	return len(p), nil
}

func (h *holdback) release() error {
	_, err := h.w.Write(h.buf)
	return err
}
