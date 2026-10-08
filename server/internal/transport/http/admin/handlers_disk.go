package admin

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"time"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
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
		Volumes: []adminapi.DiskVolume{}, Unresolved: []string{},
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
		for _, v := range d.Volumes {
			out.Volumes = append(out.Volumes, toDiskVolume(v))
		}
		out.Unresolved = nonNil(d.Unresolved)
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
	out := adminapi.DiskEscrow{Generation: int(e.Generation), Status: adminapi.DiskEscrowStatus(e.Status), Size: e.Size, CreatedAt: e.CreatedAt.UTC()}
	if e.Volume.Valid {
		out.Volume = &e.Volume.UUID
	}
	return out
}

// toDiskVolume maps a volume of health.disk (PDK-009 decision 4).
func toDiskVolume(v protocol.DiskVolume) adminapi.DiskVolume {
	out := adminapi.DiskVolume{Device: v.Device, Root: v.Root, Tokens: nonNil(v.Tokens), Keyslots: v.Keyslots, Escrowed: v.Escrowed}
	if v.UUID != "" {
		out.Uuid = &v.UUID
	}
	if v.LUKSVersion != 0 {
		out.LuksVersion = &v.LUKSVersion
	}
	if v.HeaderGeneration > 0 && v.HeaderGeneration <= 1<<31-1 {
		g := int(v.HeaderGeneration)
		out.HeaderGeneration = &g
	}
	return out
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
	header, err := h.disk.DownloadHeader(ctx, req.Id, req.Body.ConfirmHostname, req.Body.Volume, generation)
	if err != nil {
		return nil, err
	}
	filename := fmt.Sprintf("%s-luks-header-%d.img", header.Hostname, header.Generation)
	if header.Volume != "" {
		filename = fmt.Sprintf("%s-luks-header-%s-%d.img", header.Hostname, header.Volume, header.Generation)
	}
	// Hostnames are any printable text the device reported; FormatMediaType quotes or encodes them.
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	return adminapi.DownloadDeviceHeader200ApplicationoctetStreamResponse{
		Body: bytes.NewReader(header.Data), ContentLength: int64(len(header.Data)),
		Headers: adminapi.DownloadDeviceHeader200ResponseHeaders{ContentDisposition: &disposition},
	}, nil
}
