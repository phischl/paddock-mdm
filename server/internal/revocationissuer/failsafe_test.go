package revocationissuer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/platform/valkey"
	"github.com/phischl/paddock-mdm/server/internal/revocationissuer"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/valkeytest"
)

// slowSigner signs like signer, but its first slow calls sleep for delay first: an OpenBao that answers late, so the
// issuing transaction, which signs inside it, outlives the pool's transaction_timeout.
type slowSigner struct {
	signer
	delay time.Duration
	slow  atomic.Int32
}

func (s *slowSigner) SignBatch(ctx context.Context, key string, messages [][]byte) ([]bao.RawSignature, error) {
	if s.slow.Add(-1) >= 0 {
		time.Sleep(s.delay)
	}
	return s.signer.SignBatch(ctx, key, messages)
}

// timeoutIssuer replaces w's issuer with one on an organization pool capped at limit whose signer is slow for the
// first slow signatures, and returns that signer.
func (w *world) timeoutIssuer(limit time.Duration, slow int32) *slowSigner {
	w.t.Helper()
	ctx := context.Background()
	pg := pgtest.SharedPaddock(w.t)
	pool, err := db.NewOrgPool(ctx, pg.Revocation, db.Options{MaxConns: 2, TransactionTimeout: limit})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(pool.Close)
	vk, err := valkey.New(valkeytest.Start(w.t).Config)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(vk.Close)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	w.trust, _ = revocation.TrustFromKeys([]revocation.Key{{KeyID: "revocation-signing:v1", PublicKey: base64.StdEncoding.EncodeToString(pub)}})
	s := &slowSigner{signer: signer{priv}, delay: 3 * limit}
	s.slow.Store(slow)
	w.issuer = revocationissuer.New(pool, app.NewActionRunner(pool, nil, httpx.RequestID), w.proofs,
		revocationissuer.NewJTIClaims(vk), s, w.commands, w.shredder, true)
	return s
}

// TestIssueFailSafeOnTransactionTimeout (plan M17 amendment r, main §65 condition 2): when PostgreSQL ends the
// issuer's transaction for exceeding transaction_timeout, nothing of the revocation exists: the request stays
// approved, no token is recorded or put into cmd:<device_id>, the attempt is recorded as failure with
// transaction_timeout, and the next attempt issues it exactly once with a token the device accepts.
func TestIssueFailSafeOnTransactionTimeout(t *testing.T) {
	w := newWorld(t, true)
	w.timeoutIssuer(300*time.Millisecond, 1)
	dev := w.device()
	id := w.lock(dev, w.alice)

	err := w.issuer.Issue(context.Background(), w.org, id)
	if !errors.Is(err, db.ErrTransactionTimeout) {
		t.Fatalf("Issue = %v, want ErrTransactionTimeout", err)
	}
	if s, _ := w.status(id); s != "approved" {
		t.Fatalf("status after the timeout %s, want approved", s)
	}
	if _, ok := w.commands.put[id]; ok {
		t.Fatal("a token reached cmd:<device_id> although its transaction was rolled back")
	}
	var tokens int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM revocation_request WHERE id = $1 AND (envelope IS NOT NULL OR issued_at IS NOT NULL)",
		id).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatal("the rolled-back transaction left a token on the request")
	}
	if got := w.events(id); !slices.Equal(got, []string{"revocation.issued:failure"}) {
		t.Fatalf("events after the timeout %v", got)
	}

	w.issue(id)
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("status after the retry %s", s)
	}
	cmd, ok := w.commands.put[id]
	if !ok {
		t.Fatal("the retry did not put the token into cmd:<device_id>")
	}
	if tok, err := revocation.Verify(cmd.Envelope, w.trust, dev.String(), time.Now()); err != nil || tok.Action != "lock" || tok.RequestID != id.String() {
		t.Fatalf("token of the retry %+v, %v", tok, err)
	}
	if got := w.events(id); !slices.Equal(got, []string{"revocation.issued:failure", "revocation.issued:success"}) {
		t.Fatalf("events after the retry %v", got)
	}
}

// TestIssueDestroyFailSafeOnTransactionTimeout: a Destroy whose finalizing transaction (escrow rows, signature,
// issue) is ended by transaction_timeout keeps the request approved and the LUKS escrow rows, puts no token into
// cmd:<device_id>, and the retry deletes the rows and issues once. The object store deletion before the
// transaction is idempotent and is repeated.
func TestIssueDestroyFailSafeOnTransactionTimeout(t *testing.T) {
	w := newWorld(t, true)
	w.timeoutIssuer(300*time.Millisecond, 1)
	dev := w.device()
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
		VALUES (gen_random_uuid(), $1, $2, 'luks_recovery_key', 1, 'stored', '\x01', 1)`, w.org, dev)
	id := w.request("destroy", dev, w.alice, w.approval("requester", w.alice), w.approval("approver", w.bob))
	escrow := func() int {
		var n int
		if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM escrow_secret WHERE device_id = $1", dev).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if err := w.issuer.Issue(context.Background(), w.org, id); !errors.Is(err, db.ErrTransactionTimeout) {
		t.Fatalf("Issue = %v, want ErrTransactionTimeout", err)
	}
	if s, _ := w.status(id); s != "approved" {
		t.Fatalf("status after the timeout %s, want approved", s)
	}
	if _, ok := w.commands.put[id]; ok {
		t.Fatal("a token reached cmd:<device_id> although its transaction was rolled back")
	}
	if n := escrow(); n != 1 {
		t.Fatalf("%d escrow rows after the rolled-back Destroy, want 1", n)
	}

	w.issue(id)
	if s, _ := w.status(id); s != "issued" {
		t.Fatalf("status after the retry %s", s)
	}
	if n := escrow(); n != 0 {
		t.Fatalf("%d escrow rows after the retry, want 0", n)
	}
	if _, ok := w.commands.put[id]; !ok {
		t.Fatal("the retry did not put the token into cmd:<device_id>")
	}
	want := "org/" + w.org.String() + "/devices/" + dev.String() + "/luks-header/"
	if len(w.shredder.prefixes) != 2 || strings.Join(slices.Compact(w.shredder.prefixes), ",") != want {
		t.Fatalf("object store deletions %v, want the same prefix twice", w.shredder.prefixes)
	}
}
