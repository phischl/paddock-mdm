package device_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/devicecache"
)

// TestCatalogIcon (architect decision A10-14, PDK-935): the gateway resolves an entry through the device's own bundle
// pointer and redirects to a presigned GET of the icon with the bundle URL's validity; an entry of another device's
// bundle, of another organization, without an icon, an invalid entry ID and a key outside the device's organization
// are 404 not_found.
func TestCatalogIcon(t *testing.T) {
	e := newEnv(t, 0, 0)
	c, other := newClient(t), newClient(t)
	id := e.enrolled(c, "active")
	entry, plain := uuid.New(), uuid.New()
	key := "org/" + e.org.String() + "/icons/" + strings.Repeat("ab", 32) + ".png"
	if err := e.cache.PutBundlePointer(context.Background(), id, devicecache.BundlePointer{Version: 1, SHA256: "s",
		ObjectKey: "org/" + e.org.String() + "/devices/" + id.String() + "/bundles/1.dsse",
		Icons:     map[string]string{entry.String(): key}}); err != nil {
		t.Fatal(err)
	}
	icon := func(c client, dev uuid.UUID, entry string) result {
		t.Helper()
		return e.send(c, request{method: "GET", path: "/v1/catalog/" + entry + "/icon", device: dev.String()})
	}

	r := icon(c, id, entry.String())
	if r.status != http.StatusFound || r.header.Get("Location") != "https://bundles.test/paddock-bundles/"+key+"?X-Amz-Expires=120" ||
		r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("own entry: %d %v %s", r.status, r.header, r.body)
	}
	e.expectProblem(icon(c, id, plain.String()), http.StatusNotFound, "not_found")
	e.expectProblem(e.send(c, request{method: "GET", path: "/v1/catalog/x/icon", device: id.String(), skipReqCheck: true}),
		http.StatusNotFound, "not_found")

	// Another organization's device asks for the same entry: its pointer does not name it.
	otherOrg := uuid.New()
	otherID := uuid.New()
	if err := e.cache.PutDeviceKey(context.Background(), other.keyID, devicecache.DeviceKey{
		DeviceID: otherID, OrganizationID: otherOrg, Status: "active", PublicKey: other.spki,
	}, 0); err != nil {
		t.Fatal(err)
	}
	e.expectProblem(icon(other, otherID, entry.String()), http.StatusNotFound, "not_found")
	if err := e.cache.PutBundlePointer(context.Background(), otherID, devicecache.BundlePointer{Version: 1, SHA256: "s", ObjectKey: "k"}); err != nil {
		t.Fatal(err)
	}
	e.expectProblem(icon(other, otherID, entry.String()), http.StatusNotFound, "not_found")

	// A pointer naming a key of another organization is never presigned.
	if err := e.cache.PutBundlePointer(context.Background(), otherID, devicecache.BundlePointer{Version: 2, SHA256: "s", ObjectKey: "k",
		Icons: map[string]string{entry.String(): key}}); err != nil {
		t.Fatal(err)
	}
	e.expectProblem(icon(other, otherID, entry.String()), http.StatusNotFound, "not_found")

	// Unsigned is 401.
	r = e.send(c, request{method: "GET", path: "/v1/catalog/" + entry.String() + "/icon", device: id.String(),
		mutate: func(r *http.Request, _ *[]byte) { r.Header.Del("Paddock-Signature") }, skipReqCheck: true})
	e.expectProblem(r, http.StatusUnauthorized, "invalid_signature")
}
