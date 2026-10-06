package escrowreader

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// Client is the api's client of the escrow-reader (app.EscrowDecrypter).
type Client struct {
	url    string
	secret []byte
	http   *http.Client
}

// NewClient creates a client for the escrow-reader at baseURL (http://<host>:<port>) with the shared bearer secret.
func NewClient(baseURL, secret string) *Client {
	return &Client{url: strings.TrimRight(baseURL, "/") + DecryptPath, secret: []byte(secret),
		http: &http.Client{Timeout: 30 * time.Second}}
}

// Decrypt implements app.EscrowDecrypter; a refusal wraps app.ErrEscrowRefused with the escrow-reader's code.
func (c *Client) Decrypt(ctx context.Context, req app.EscrowDecryptRequest) (map[uuid.UUID][]byte, error) {
	body, err := json.Marshal(decryptRequest{OrganizationID: req.OrganizationID, DeviceID: req.DeviceID,
		EscrowIDs: req.EscrowIDs, StepUpIDToken: req.StepUpIDToken, Purpose: req.Purpose})
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Authorization", "Bearer "+string(c.secret))
	hr.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("escrow reader: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("escrow reader: %w", err)
	}
	defer clear(data)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		return nil, fmt.Errorf("escrow reader: HTTP %d", resp.StatusCode)
	}
	if !hmac.Equal([]byte(resp.Header.Get(macHeader)), []byte(mac(c.secret, data))) {
		return nil, fmt.Errorf("escrow reader: answer without valid MAC (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusForbidden {
		var r refusal
		_ = json.Unmarshal(data, &r)
		return nil, fmt.Errorf("%w: %s", app.ErrEscrowRefused, r.Code)
	}
	var out decryptResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("escrow reader: %w", err)
	}
	return out.Plaintexts, nil
}
