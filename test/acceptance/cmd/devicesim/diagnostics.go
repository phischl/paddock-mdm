package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
)

// uploadDiagnostics checks in until the device holds the escrow key of a bundle and a collect_status command, then
// seals a fixed archive for the command as the agent does, announces it with the key version, uploads it and reports
// the result. It returns the hex SHA-256 of the plain archive, which a download must reproduce.
func uploadDiagnostics(ctx context.Context, dev *devicesim.Device) (string, error) {
	dev.SchemaVersions = []int{1, 2}
	var keys *bundle.Keys
	var cmd *command.Command
	for keys == nil || cmd == nil {
		out, res, err := dev.Checkin(ctx)
		if err != nil || res.Status != http.StatusOK {
			return "", fmt.Errorf("checkin: %v HTTP %d", err, res.Status)
		}
		if out.Bundle != nil && keys == nil {
			b, err := dev.Fetch(ctx, out.Bundle)
			if err != nil {
				return "", err
			}
			if b.Keys != nil && b.Keys.EscrowWrap != nil {
				keys = b.Keys
			}
		}
		for _, env := range out.Commands {
			if c := collectStatus(env); c != nil {
				cmd = c
			}
		}
		if keys != nil && cmd != nil {
			break
		}
		select {
		case <-ctx.Done():
			return "", errors.New("no bundle with the escrow key or no collect_status command")
		case <-time.After(2500 * time.Millisecond):
		}
	}
	archive, err := fixtureArchive(cmd.CommandID)
	if err != nil {
		return "", err
	}
	pub, err := escrow.ParsePublicKey(keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		return "", err
	}
	version, err := escrow.KeyVersion(keys.EscrowWrap.KeyID)
	if err != nil {
		return "", err
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	sealed, nonce, err := escrow.SealObject(dek, cmd.CommandID, bytes.NewReader(archive))
	if err != nil {
		return "", err
	}
	wrapped, err := escrow.Encrypt(pub, dek)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(sealed)
	res, err := dev.Do(ctx, devicesim.Request{Method: http.MethodPost, Path: "/v1/diagnostics", Body: protocol.DiagnosticsRequest{
		CommandID: cmd.CommandID, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(sealed)),
		Nonce: base64.StdEncoding.EncodeToString(nonce), WrappedDEK: wrapped, KeyVersion: version,
	}})
	if err != nil || res.Status != http.StatusAccepted {
		return "", fmt.Errorf("announce: %v HTTP %d %s", err, res.Status, res.Body)
	}
	var answer protocol.DiagnosticsResponse
	if err := json.Unmarshal(res.Body, &answer); err != nil {
		return "", err
	}
	if status, err := dev.Upload(ctx, answer.UploadURL, sealed); err != nil || status != http.StatusOK {
		return "", fmt.Errorf("upload: %v HTTP %d", err, status)
	}
	result, _ := json.Marshal(command.CollectStatusResult{Uploaded: true, Files: 1, Bytes: int64(len(archive))})
	if res, err := dev.CommandResult(ctx, cmd.CommandID, protocol.CommandSucceeded, result); err != nil || res.Status != http.StatusAccepted {
		return "", fmt.Errorf("result: %v HTTP %d %s", err, res.Status, res.Body)
	}
	plain := sha256.Sum256(archive)
	return hex.EncodeToString(plain[:]), nil
}

// collectStatus is the command of a delivered envelope when it is a collect_status command.
func collectStatus(env json.RawMessage) *command.Command {
	_, payload, err := dsse.Decode(env)
	if err != nil {
		return nil
	}
	var c command.Command
	if json.Unmarshal(payload, &c) != nil || c.Type != command.TypeCollectStatus {
		return nil
	}
	return &c
}

// fixtureArchive is a tar.gz with the manifest of the bundle only.
func fixtureArchive(id string) ([]byte, error) {
	manifest, _ := json.Marshal(map[string]any{"schema": "paddock.diagnostics.v1", "request_id": id, "entries": []any{}})
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(manifest); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
