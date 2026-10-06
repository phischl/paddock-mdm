package admin

import (
	"bytes"
	"context"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GenerateAutoinstall(ctx context.Context, req adminapi.GenerateAutoinstallRequestObject) (adminapi.GenerateAutoinstallResponseObject, error) {
	b := req.Body
	keys := make([]protocol.BundleKey, len(b.EnrollmentConfig.BundleKeys))
	for i, k := range b.EnrollmentConfig.BundleKeys {
		keys[i] = protocol.BundleKey{KeyID: k.KeyId, PublicKey: k.PublicKey}
	}
	out, err := h.autoinstall.Generate(ctx, app.AutoinstallRequest{
		EnrollmentConfig: protocol.EnrollmentConfig{
			ServerURL: b.EnrollmentConfig.ServerUrl, OrganizationID: b.EnrollmentConfig.OrganizationId.String(),
			Token: b.EnrollmentConfig.Token, BundleKeys: keys,
		},
		Release: string(b.Release), Hostname: b.Hostname, Locale: b.Locale, KeyboardLayout: b.KeyboardLayout, Timezone: b.Timezone,
	})
	if err != nil {
		return nil, err
	}
	return adminapi.GenerateAutoinstall200TextyamlResponse{Body: bytes.NewReader(out), ContentLength: int64(len(out))}, nil
}
