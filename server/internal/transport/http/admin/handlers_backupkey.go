package admin

import (
	"context"

	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetBackupKey(ctx context.Context, _ adminapi.GetBackupKeyRequestObject) (adminapi.GetBackupKeyResponseObject, error) {
	st, err := h.backupKeys.Status(ctx)
	if err != nil {
		return nil, err
	}
	return adminapi.GetBackupKey200JSONResponse(toBackupKeyStatus(st)), nil
}

func (h *handlers) GenerateBackupKey(ctx context.Context, _ adminapi.GenerateBackupKeyRequestObject) (adminapi.GenerateBackupKeyResponseObject, error) {
	k, err := h.backupKeys.Generate(ctx)
	if err != nil {
		return nil, err
	}
	// The only response that carries the key text: no cache may keep it (plan M15 decision 7).
	noStore := "no-store"
	return adminapi.GenerateBackupKey201JSONResponse{
		Body: adminapi.BackupKeyGenerated{KeyId: k.KeyID, Key: k.Text, Fingerprint: k.Fingerprint, Positions: k.Positions[:],
			DownloadName: k.DownloadName},
		Headers: adminapi.GenerateBackupKey201ResponseHeaders{CacheControl: &noStore},
	}, nil
}

func (h *handlers) ConfirmBackupKey(ctx context.Context, req adminapi.ConfirmBackupKeyRequestObject) (adminapi.ConfirmBackupKeyResponseObject, error) {
	if req.Body == nil {
		return nil, problem.InvalidRequest.WithDetail("answer is required")
	}
	k, err := h.backupKeys.Confirm(ctx, req.Id, req.Body.Answer)
	if err != nil {
		return nil, err
	}
	return adminapi.ConfirmBackupKey200JSONResponse(toBackupKey(k)), nil
}

func (h *handlers) DiscardBackupKey(ctx context.Context, req adminapi.DiscardBackupKeyRequestObject) (adminapi.DiscardBackupKeyResponseObject, error) {
	k, err := h.backupKeys.Discard(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return adminapi.DiscardBackupKey200JSONResponse(toBackupKey(k)), nil
}
