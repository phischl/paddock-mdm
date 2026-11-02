package acceptance

import (
	"bytes"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/sink"
)

var pseudonymPattern = regexp.MustCompile(`^u_[0-9a-f]{24}$`)

// TestNotificationsEmail is gate N6 (plan M9 §9): with the development notifier pointed at the acceptance SMTP sink,
// an e-mail destination with two recipients and pseudonymize_users receives an admin.login and a tamper event as one
// plain-text message to both recipients, marked Auto-Submitted, with the administrator's name replaced by a pseudonym
// and no parameters; the organization resolves that pseudonym to the name after a step-up, recorded once.
func TestNotificationsEmail(t *testing.T) {
	admin := adminUser(t, "n6")
	as := adminStepper(admin)
	org := orgOf(t, admin.Portal)
	suffix := uniqueSuffix()
	d := activeDevice(t, admin.Portal, "", "n6-"+suffix)
	smtpSink := sink.StartSMTP(t)

	recipients := []string{"secops-" + suffix + "@example.org", "ciso-" + suffix + "@example.org"}
	body := map[string]any{"type": "email", "name": destinationName("n6"), "enabled": true, "filter_mode": "custom",
		"codes": []string{"admin.login", tamperCode}, "recipients": recipients, "pseudonymize_users": true,
		"include_params": false, "email_min_interval_s": 60}
	dest, _ := createDestination(t, as, orgDestinations, body)
	path := orgDestinations + "/" + dest.ID
	waitStarted(t, admin.Portal, path)

	// Disabled while the two events are recorded, so that the first scan after enabling sees both and they leave as
	// one message instead of two separated by the digest interval.
	admin.stepUp(t)
	body["enabled"] = false
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, body), http.StatusOK, "")
	idx := auditIndex(t)
	loginsOf := func() int {
		logins, err := idx.Events(testContext(t, time.Minute), org, "code = 'admin.login' AND actor->>'display' = $1", admin.username)
		if err != nil {
			t.Fatal(err)
		}
		return len(logins)
	}
	before := loginsOf()
	withoutStepUp(t, admin)
	const file = "n6-evil"
	sendSudoersEvent(t, d, 1, file)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		logins := loginsOf()
		tampers, err := idx.Events(testContext(t, time.Minute), org, "code = '"+tamperCode+"' AND target->>'id' = $1", d.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		if logins > before && len(tampers) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d logins, %d tamper events indexed", logins, before+1, len(tampers))
		}
		time.Sleep(time.Second)
	}
	admin.stepUp(t)
	body["enabled"], body["cursor"] = true, "continue"
	expectStatus(t, call(t, admin.Portal, http.MethodPut, path, body), http.StatusOK, "")

	ofDestination := func(mails []sink.Mail) []sink.Mail {
		var out []sink.Mail
		for _, m := range mails {
			if msg, err := mail.ReadMessage(bytes.NewReader(m.Data)); err == nil && msg.Header.Get("X-Paddock-Destination") == dest.ID {
				out = append(out, m)
			}
		}
		return out
	}
	got := ofDestination(smtpSink.WaitMail(t, deliveryTimeout, "the e-mail", func(m []sink.Mail) bool {
		return len(ofDestination(m)) > 0
	}))
	if len(got) != 1 {
		t.Fatalf("%d messages for the destination, want 1", len(got))
	}
	m := got[0]
	if !slices.Equal(m.To, recipients) || m.From == "" {
		t.Fatalf("envelope from %q to %v, want %v", m.From, m.To, recipients)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(m.Data))
	if err != nil {
		t.Fatal(err)
	}
	h := msg.Header
	if h.Get("Auto-Submitted") != "auto-generated" || h.Get("X-Paddock-Delivery") == "" ||
		!strings.HasPrefix(h.Get("X-Paddock-Forward-Seq"), "1-") || !strings.HasPrefix(h.Get("Subject"), "[Paddock] ") ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("headers %v", h)
	}
	for _, r := range recipients {
		if !strings.Contains(h.Get("To"), r) {
			t.Fatalf("To %q lacks %s", h.Get("To"), r)
		}
	}
	raw, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.Contains(text, "  "+tamperCode+"  ") || !strings.Contains(text, "/devices/"+d.DeviceID+"\n") {
		t.Fatalf("no tamper block for the device:\n%s", text)
	}
	if strings.Contains(text, "params:") || strings.Contains(text, file) {
		t.Fatalf("parameters in a message without include_params:\n%s", text)
	}
	if strings.Contains(text, admin.username) {
		t.Fatalf("the administrator's name appears despite pseudonymize_users:\n%s", text)
	}
	var pseudonyms []string
	for _, block := range strings.Split(text, "\n\n") {
		lines := strings.Split(block, "\n")
		if !strings.Contains(lines[0], "  admin.login  ") {
			continue
		}
		for _, l := range lines[1:] {
			if a, ok := strings.CutPrefix(l, "  actor: "); ok {
				if !pseudonymPattern.MatchString(a) {
					t.Fatalf("admin.login actor %q is not a pseudonym", a)
				}
				if !slices.Contains(pseudonyms, a) {
					pseudonyms = append(pseudonyms, a)
				}
			}
		}
	}
	if len(pseudonyms) == 0 {
		t.Fatalf("no admin.login block:\n%s", text)
	}

	// Other gates may sign in to the same organization meanwhile; the administrator's login is one of the blocks.
	for _, p := range pseudonyms {
		if resolvePseudonym(t, admin, path, p) == admin.username {
			return
		}
	}
	t.Fatalf("none of the pseudonyms %v resolves to %s", pseudonyms, admin.username)
}

// resolvePseudonym asks the notifier for the name behind pseudonym after a step-up, checks that the request was
// recorded once, and returns the answer.
func resolvePseudonym(t *testing.T, admin *mfaUser, path, pseudonym string) string {
	t.Helper()
	admin.stepUp(t)
	res := call(t, admin.Portal, http.MethodPost, path+"/resolve-pseudonym", map[string]any{"pseudonym": pseudonym})
	expectStatus(t, res, http.StatusAccepted, "")
	var lookup struct {
		LookupID string `json:"lookup_id"`
	}
	if err := res.JSON(&lookup); err != nil || lookup.LookupID == "" {
		t.Fatalf("resolve: %s", res.Body)
	}
	deleteLookupOnCleanup(t, lookup.LookupID)
	ev := expectOneEvent(t, admin.Portal, res.RequestID, "notification.pseudonym_resolved", "success")
	if ev.Params["pseudonym"] != pseudonym {
		t.Fatalf("resolve event params %v", ev.Params)
	}
	var answer struct {
		Username *string `json:"username"`
		Resolved bool    `json:"resolved"`
	}
	deadline := time.Now().Add(time.Minute)
	for {
		got := call(t, admin.Portal, http.MethodGet, path+"/resolve-pseudonym/"+lookup.LookupID, nil)
		expectStatus(t, got, http.StatusOK, "")
		if err := got.JSON(&answer); err != nil {
			t.Fatal(err)
		}
		if answer.Resolved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lookup of %s not resolved within a minute", pseudonym)
		}
		time.Sleep(time.Second)
	}
	if answer.Username == nil {
		return ""
	}
	return *answer.Username
}
