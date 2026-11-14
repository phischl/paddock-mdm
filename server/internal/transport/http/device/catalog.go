package device

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
)

// IconURLTTL is the validity of the presigned GET a catalog icon redirect names; the device follows it at once, as
// it does a bundle URL (architect decision A10-14).
const IconURLTTL = BundleURLTTL

// catalogIcon answers GET /v1/catalog/{entry_id}/icon with a redirect to the entry's icon in the bundles bucket
// (architect decision A10-14). The entry resolves only through the device's own bundle pointer, so a device reaches
// the icons its bundle names and nothing of another organization; every other entry is 404 not_found.
func (g *gateway) catalogIcon(w http.ResponseWriter, r *http.Request) {
	dev, err := g.authenticateDevice(w, r, maxBody)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	entry, err := uuid.Parse(r.PathValue("entry_id"))
	if err != nil {
		g.fail(w, r, errNotFound)
		return
	}
	p, ok, err := g.d.Cache.BundlePointer(r.Context(), dev.id)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	key := p.Icons[entry.String()]
	if !ok || key == "" {
		g.fail(w, r, errNotFound)
		return
	}
	// The compiler only writes keys below the device's organization; a key outside it is never presigned.
	if !strings.HasPrefix(key, "org/"+dev.key.OrganizationID.String()+"/icons/") {
		slog.ErrorContext(r.Context(), "bundle pointer names an icon outside the device's organization; refused",
			"device_id", dev.id, "request_id", httpx.RequestID(r.Context()))
		g.fail(w, r, errNotFound)
		return
	}
	url, err := g.d.Presigner.PresignGet(r.Context(), key, IconURLTTL)
	if err != nil {
		g.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusFound)
}
