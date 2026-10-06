package admin

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"time"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

func (h *handlers) GetDeviceDisk(ctx context.Context, req adminapi.GetDeviceDiskRequestObject) (adminapi.GetDeviceDiskResponseObject, error) {
	s, err := h.disk.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := adminapi.GetDeviceDisk200JSONResponse{
		Tokens: []string{}, RecoveryKeys: []adminapi.DiskEscrow{}, Headers: []adminapi.DiskEscrow{}, ReportedAt: utcPtr(s.ReportedAt),
	}
	if d := s.Health; d != nil {
		state := adminapi.DiskState(d.State)
		out.State, out.Keyslots = &state, d.Keyslots
		if d.Tokens != nil {
			out.Tokens = d.Tokens
		}
		if d.LUKSVersion != 0 {
			out.LuksVersion = &d.LUKSVersion
		}
	}
	for _, e := range s.Escrows {
		if e.Kind == escrow.KindLUKSHeader {
			out.Headers = append(out.Headers, toDiskEscrow(e))
		} else {
			out.RecoveryKeys = append(out.RecoveryKeys, toDiskEscrow(e))
		}
	}
	if c := s.LastKeyslotChange; c != nil {
		out.LastKeyslotChange = &struct {
			After  []string  `json:"after"`
			At     time.Time `json:"at"`
			Before []string  `json:"before"`
		}{After: nonNil(c.After), At: c.At.UTC(), Before: nonNil(c.Before)}
	}
	return out, nil
}

func toDiskEscrow(e pgstore.EscrowSecret) adminapi.DiskEscrow {
	return adminapi.DiskEscrow{Generation: int(e.Generation), Status: adminapi.DiskEscrowStatus(e.Status), Size: e.Size, CreatedAt: e.CreatedAt.UTC()}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *handlers) RevealDeviceRecoveryKey(ctx context.Context, req adminapi.RevealDeviceRecoveryKeyRequestObject) (adminapi.RevealDeviceRecoveryKeyResponseObject, error) {
	generation, key, err := h.disk.RevealRecoveryKey(ctx, req.Id, req.Body.ConfirmHostname)
	if err != nil {
		return nil, err
	}
	return adminapi.RevealDeviceRecoveryKey200JSONResponse{Generation: generation, RecoveryKey: key}, nil
}

func (h *handlers) DownloadDeviceHeader(ctx context.Context, req adminapi.DownloadDeviceHeaderRequestObject) (adminapi.DownloadDeviceHeaderResponseObject, error) {
	generation := 0
	if req.Body.Generation != nil {
		generation = *req.Body.Generation
	}
	header, err := h.disk.DownloadHeader(ctx, req.Id, req.Body.ConfirmHostname, generation)
	if err != nil {
		return nil, err
	}
	// Hostnames are any printable text the device reported; FormatMediaType quotes or encodes them.
	disposition := mime.FormatMediaType("attachment", map[string]string{
		"filename": fmt.Sprintf("%s-luks-header-%d.img", header.Hostname, header.Generation),
	})
	return adminapi.DownloadDeviceHeader200ApplicationoctetStreamResponse{
		Body: bytes.NewReader(header.Data), ContentLength: int64(len(header.Data)),
		Headers: adminapi.DownloadDeviceHeader200ResponseHeaders{ContentDisposition: &disposition},
	}, nil
}
