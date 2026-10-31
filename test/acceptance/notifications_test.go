package acceptance

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/sink"
)

type notificationDestination struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Enabled    bool    `json:"enabled"`
	URLDisplay *string `json:"url_display"`
	Secret     *string `json:"secret"`
	State      struct {
		Status string `json:"status"`
	} `json:"state"`
}

// stepper is a session and the renewal of its step-up.
type stepper struct {
	*env.Portal
	stepUp func(t *testing.T)
}

func adminStepper(u *mfaUser) stepper { return stepper{Portal: u.Portal, stepUp: u.stepUp} }

// rootStepper is a platform administrator session of its own (PDK-445: never step up a shared session).
func rootStepper(t *testing.T) stepper {
	t.Helper()
	root := login(t, env.PlatformAdmin)
	return stepper{Portal: root, stepUp: func(t *testing.T) { freshStepUp(t, root, env.PlatformAdmin) }}
}

// createDestination creates a destination with a stepped-up session, deletes it when the test ends, and returns it
// with the secret of the 201 body.
func createDestination(t *testing.T, u stepper, collection string, body map[string]any) (notificationDestination, env.Response) {
	t.Helper()
	u.stepUp(t)
	res := call(t, u.Portal, http.MethodPost, collection, body)
	expectStatus(t, res, http.StatusCreated, "")
	var d notificationDestination
	if err := res.JSON(&d); err != nil || d.ID == "" {
		t.Fatalf("created destination: %v %s", err, res.Body)
	}
	deleteDestinationOnCleanup(t, u.Portal, u.stepUp, collection+"/"+d.ID)
	return d, res
}

// TestNotificationDestinations covers the CRUD parts of plan M9 §3.4 and the validation and secrecy parts of gate
// N5 against the stack: the secret is shown once, the URL never, every change needs a step-up and is audited once,
// another organization's destination is not found, and platform destinations belong to platform administrators.
func TestNotificationDestinations(t *testing.T) {
	admin := adminUser(t, "n-admin")
	as := adminStepper(admin)
	const collection = "/api/v1/notification-destinations"

	t.Run("create shows the secret once and never the URL", func(t *testing.T) {
		d, res := createDestination(t, as, collection, webhookBody(destinationName("n5"), notificationURL))
		if d.Secret == nil || len(*d.Secret) != 43 {
			t.Fatalf("201 without a 43-character secret: %s", res.Body)
		}
		if d.URLDisplay == nil || *d.URLDisplay != "https://192.0.2.1/…" || d.State.Status != "active" {
			t.Fatalf("created %+v", d)
		}
		if loc := res.Header.Get("Location"); loc != collection+"/"+d.ID {
			t.Fatalf("Location %q", loc)
		}
		ev := expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_created", "success")
		if ev.Params["url_display"] != "https://192.0.2.1/…" || !ev.Actor.StepUp {
			t.Fatalf("event params %v step-up %t", ev.Params, ev.Actor.StepUp)
		}
		for _, get := range []string{collection + "/" + d.ID, collection + "?page_size=100"} {
			got := call(t, admin.Portal, http.MethodGet, get, nil)
			expectStatus(t, got, http.StatusOK, "")
			for _, leak := range []string{*d.Secret, "n-secret", "/services/", `"secret"`, `"url"`} {
				if bytes.Contains(got.Body, []byte(leak)) {
					t.Fatalf("GET %s shows %q: %s", get, leak, got.Body)
				}
			}
		}
		raw := fmt.Sprint(ev.Params)
		if strings.Contains(raw, *d.Secret) || strings.Contains(raw, "n-secret") {
			t.Fatalf("audit params carry a secret: %v", ev.Params)
		}
		auditor := call(t, login(t, env.Bob), http.MethodGet, collection+"/"+d.ID, nil)
		expectStatus(t, auditor, http.StatusOK, "")
	})

	t.Run("step-up, role and name", func(t *testing.T) {
		res := call(t, withoutStepUp(t, admin), http.MethodPost, collection, webhookBody(destinationName("nostep"), notificationURL))
		expectStatus(t, res, http.StatusForbidden, "step_up_required")
		expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_created", "denied")
		res = call(t, operatorUser(t).Portal, http.MethodPost, collection, webhookBody(destinationName("op"), notificationURL))
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		res = call(t, operatorUser(t).Portal, http.MethodGet, collection, nil)
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		d, _ := createDestination(t, as, collection, webhookBody(destinationName("dup"), notificationURL))
		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, collection, webhookBody(d.Name, notificationURL))
		expectStatus(t, res, http.StatusConflict, "already_exists")
	})

	// Gate N5: the rules that hold on every stack. Private addresses and plain http are refused by the api's
	// production policy (unit- and integration-tested in server/internal/app); this development stack admits them
	// only because PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE=true (compose.dev.yaml), so its acceptance sinks on the host
	// can receive deliveries.
	t.Run("validation", func(t *testing.T) {
		for _, url := range []string{"https://user:pw@93.184.215.14/", "https://93.184.215.14:80/", "not a url"} {
			admin.stepUp(t)
			res := call(t, admin.Portal, http.MethodPost, collection, webhookBody(destinationName("bad"), url))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			if detail := problemDetail(t, res); !strings.Contains(detail, "invalid webhook URL") || strings.Contains(detail, "pw@") {
				t.Errorf("%s: detail %q", url, detail)
			}
			expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_created", "failure")
		}
		for _, url := range []string{"http://127.0.0.1:8080/", "https://10.0.0.1/"} {
			d, _ := createDestination(t, as, collection, webhookBody(destinationName("dev"), url))
			if d.URLDisplay == nil {
				t.Fatalf("%s: no url_display", url)
			}
		}
		body := webhookBody(destinationName("hb"), notificationURL)
		body["heartbeat_interval_s"] = 30
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, collection, body)
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		if !strings.Contains(problemDetail(t, res), "heartbeat_interval_s") {
			t.Errorf("heartbeat detail %q", problemDetail(t, res))
		}
		body = webhookBody(destinationName("custom"), notificationURL)
		body["filter_mode"], body["codes"] = "custom", []string{"admin.login", "no.such_code"}
		res = call(t, admin.Portal, http.MethodPost, collection, body)
		expectStatus(t, res, http.StatusBadRequest, "unknown_code")

		caps := call(t, admin.Portal, http.MethodGet, "/api/v1/notification-capabilities", nil)
		expectStatus(t, caps, http.StatusOK, "")
		var c struct {
			Email bool `json:"email"`
		}
		if err := caps.JSON(&c); err != nil || c.Email {
			t.Fatalf("capabilities %s (the development stack has no SMTP relay)", caps.Body)
		}
		res = call(t, admin.Portal, http.MethodPost, collection, map[string]any{"type": "email", "name": destinationName("mail"),
			"enabled": true, "filter_mode": "all", "recipients": []string{"secops@example.org"}})
		expectStatus(t, res, http.StatusConflict, "email_not_configured")
	})

	t.Run("update, enable with cursor, rotate, test", func(t *testing.T) {
		// The sink holds its answer, so that the test delivery the notifier attempts stays pending for the second
		// request below.
		held := sink.Start(t)
		held.Hold(30 * time.Second)
		d, _ := createDestination(t, as, collection, webhookBody(destinationName("upd"), notificationURL))
		path := collection + "/" + d.ID
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": d.Name, "enabled": false, "filter_mode": "all"})
		expectStatus(t, res, http.StatusOK, "")
		var got notificationDestination
		if err := res.JSON(&got); err != nil || got.Enabled || got.URLDisplay == nil || *got.URLDisplay != "https://192.0.2.1/…" {
			t.Fatalf("update without url: %s", res.Body)
		}
		res = call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": d.Name, "enabled": false, "filter_mode": "all",
			"url": "https://user:pw@93.184.215.14/"})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		res = call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": d.Name, "enabled": true, "filter_mode": "all"})
		expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		res = call(t, admin.Portal, http.MethodPut, path, map[string]any{"name": d.Name, "enabled": true, "filter_mode": "all",
			"cursor": "skip", "url": held.URL()})
		expectStatus(t, res, http.StatusOK, "")
		ev := expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_updated", "success")
		if ev.Params["cursor"] != "skip" || fmt.Sprint(ev.Params["changed"]) != "[enabled url]" {
			t.Fatalf("update params %v", ev.Params)
		}

		admin.stepUp(t)
		res = call(t, admin.Portal, http.MethodPost, path+"/rotate-secret", nil)
		expectStatus(t, res, http.StatusOK, "")
		var rotated struct {
			Secret string `json:"secret"`
		}
		if err := res.JSON(&rotated); err != nil || len(rotated.Secret) != 43 || rotated.Secret == *d.Secret {
			t.Fatalf("rotate: %s", res.Body)
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_secret_rotated", "success")

		res = call(t, admin.Portal, http.MethodPost, path+"/test", nil)
		expectStatus(t, res, http.StatusAccepted, "")
		var test struct {
			DeliveryID string `json:"delivery_id"`
		}
		if err := res.JSON(&test); err != nil || test.DeliveryID == "" {
			t.Fatalf("test: %s", res.Body)
		}
		expectOneEvent(t, admin.Portal, res.RequestID, "notification.test_requested", "success")
		res = call(t, admin.Portal, http.MethodPost, path+"/test", nil)
		expectStatus(t, res, http.StatusConflict, "invalid_state")
	})

	t.Run("resolve pseudonym", func(t *testing.T) {
		body := webhookBody(destinationName("pseudo"), notificationURL)
		body["pseudonymize_users"] = true
		d, _ := createDestination(t, as, collection, body)
		const pseudonym = "u_0123456789abcdef01234567"
		admin.stepUp(t)
		res := call(t, admin.Portal, http.MethodPost, collection+"/"+d.ID+"/resolve-pseudonym", map[string]any{"pseudonym": pseudonym})
		expectStatus(t, res, http.StatusAccepted, "")
		var lookup struct {
			LookupID string `json:"lookup_id"`
		}
		if err := res.JSON(&lookup); err != nil || lookup.LookupID == "" {
			t.Fatalf("resolve: %s", res.Body)
		}
		deleteLookupOnCleanup(t, lookup.LookupID)
		lookupPath := collection + "/" + d.ID + "/resolve-pseudonym/"
		res2 := call(t, admin.Portal, http.MethodPost, collection+"/"+d.ID+"/resolve-pseudonym", map[string]any{"pseudonym": pseudonym})
		if res2.Status == http.StatusAccepted {
			// The stack's notifier answered the first lookup between the two requests: a resolved lookup does not
			// block the next one. The refusal while it is unresolved is integration-tested (TestNotificationPseudonymLookup).
			if err := res2.JSON(&lookup); err != nil || lookup.LookupID == "" {
				t.Fatalf("second resolve: %s", res2.Body)
			}
			deleteLookupOnCleanup(t, lookup.LookupID)
			t.Logf("the notifier resolved the first lookup before the second request")
		} else {
			expectStatus(t, res2, http.StatusConflict, "invalid_state")
		}
		ev := expectOneEvent(t, admin.Portal, res.RequestID, "notification.pseudonym_resolved", "success")
		if ev.Params["pseudonym"] != pseudonym || ev.Target == nil || ev.Target.Type != "organization" {
			t.Fatalf("resolve event %+v", ev)
		}
		// The notifier resolves the lookup within a round; the pseudonym stands for nobody, so the name is empty, and
		// the answer is shown once.
		var got env.Response
		deadline := time.Now().Add(time.Minute)
		for {
			got = call(t, admin.Portal, http.MethodGet, lookupPath+lookup.LookupID, nil)
			expectStatus(t, got, http.StatusOK, "")
			if bytes.Contains(got.Body, []byte(`"resolved":true`)) || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		var answer struct {
			Pseudonym string  `json:"pseudonym"`
			Username  *string `json:"username"`
			Resolved  bool    `json:"resolved"`
		}
		if err := got.JSON(&answer); err != nil || !answer.Resolved || answer.Pseudonym != pseudonym ||
			(answer.Username != nil && *answer.Username != "") {
			t.Fatalf("lookup answer %s", got.Body)
		}
		expectStatus(t, call(t, admin.Portal, http.MethodGet, lookupPath+lookup.LookupID, nil), http.StatusNotFound, "not_found")
	})

	t.Run("another organization", func(t *testing.T) {
		d, _ := createDestination(t, as, collection, webhookBody(destinationName("iso"), notificationURL))
		carol := login(t, env.Carol)
		stepUp(t, carol, env.Carol, true)
		for _, r := range []struct{ method, path string }{
			{http.MethodGet, collection + "/" + d.ID},
			{http.MethodPut, collection + "/" + d.ID},
			{http.MethodDelete, collection + "/" + d.ID},
			{http.MethodPost, collection + "/" + d.ID + "/rotate-secret"},
			{http.MethodPost, collection + "/" + d.ID + "/test"},
		} {
			var body any
			if r.method == http.MethodPut {
				body = map[string]any{"name": "taken over", "enabled": true, "filter_mode": "all"}
			}
			expectStatus(t, call(t, carol, r.method, r.path, body), http.StatusNotFound, "not_found")
		}
	})

	t.Run("platform", func(t *testing.T) {
		root := rootStepper(t)
		const platform = "/api/platform/v1/notification-destinations"
		d, res := createDestination(t, root, platform, webhookBody(destinationName("platform"), notificationURL))
		if d.Secret == nil {
			t.Fatalf("platform create without secret: %s", res.Body)
		}
		idx := auditIndex(t)
		expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "notification.destination_created", "success", auditPollTimeout)
		expectStatus(t, call(t, admin.Portal, http.MethodGet, platform, nil), http.StatusForbidden, "forbidden")
		expectStatus(t, call(t, admin.Portal, http.MethodGet, collection+"/"+d.ID, nil), http.StatusNotFound, "not_found")
		res = call(t, admin.Portal, http.MethodPost, platform, webhookBody(destinationName("org"), notificationURL))
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		expectOneEvent(t, admin.Portal, res.RequestID, "notification.destination_created", "denied")
		got := call(t, root.Portal, http.MethodGet, platform+"/"+d.ID, nil)
		expectStatus(t, got, http.StatusOK, "")
	})
}
