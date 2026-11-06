package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// devTarget is a development backup target of compose.backup.dev.yaml (plan M15 decision 18).
type devTarget struct {
	name string
	body func() (map[string]any, error)
	// local targets need the host's mount marker (written by ./paddock backup-target apply on a host).
	local bool
}

var devTargets = []devTarget{
	{name: "dev-s3", body: func() (map[string]any, error) {
		access, err := stack.Secret("backup_dev_target_access_key")
		if err != nil {
			return nil, err
		}
		secret, err := stack.Secret("backup_dev_target_secret_key")
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": "dev-s3", "type": "s3", "enabled": true, "s3": map[string]any{
			"endpoint": "http://audit-rustfs:9000", "bucket": "paddock-backup", "access_key": access, "secret_key": secret}}, nil
	}},
	{name: "dev-local", local: true, body: func() (map[string]any, error) {
		return map[string]any{"name": "dev-local", "type": "local", "enabled": true,
			"local": map[string]any{"path": "dev-local"}}, nil
	}},
}

// seedBackupTargets creates the development backup targets once (make dev-seed BACKUP=1) and marks the local one as
// mounted in the volume backup-local-dev, which compose.backup.dev.yaml mounts as the backup role's targets directory.
func seedBackupTargets(ctx context.Context, admin *env.Portal) error {
	if back, err := admin.StepUp(ctx, env.PlatformAdmin, "/"); err != nil || strings.Contains(back, "stepup=failed") {
		return fmt.Errorf("step-up of %s: %v (%s)", env.PlatformAdmin, err, back)
	}
	for _, t := range devTargets {
		id, rev, err := ensureTarget(ctx, admin, t)
		if err != nil {
			return err
		}
		if t.local {
			if err := markMounted(ctx, id, rev); err != nil {
				return err
			}
		}
		fmt.Printf("backup target %s ready\n", t.name)
	}
	return nil
}

// ensureTarget returns the target's ID and host revision, creating it when no target of that name exists.
func ensureTarget(ctx context.Context, admin *env.Portal, t devTarget) (string, int, error) {
	type target struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		HostRevision int    `json:"host_revision"`
	}
	res, err := admin.Do(ctx, http.MethodGet, "/api/platform/v1/backup/targets?page_size=100&q="+url.QueryEscape(t.name), nil)
	if err != nil {
		return "", 0, err
	}
	var page struct{ Items []target }
	if err := res.JSON(&page); err != nil {
		return "", 0, fmt.Errorf("list backup targets: HTTP %d: %w", res.Status, err)
	}
	for _, it := range page.Items {
		if it.Name == t.name {
			return it.ID, it.HostRevision, nil
		}
	}
	body, err := t.body()
	if err != nil {
		return "", 0, fmt.Errorf("%w (run make dev-secrets)", err)
	}
	res, err = admin.Do(ctx, http.MethodPost, "/api/platform/v1/backup/targets", body)
	if err != nil {
		return "", 0, err
	}
	var created target
	if res.Status != http.StatusCreated || res.JSON(&created) != nil {
		return "", 0, fmt.Errorf("create backup target %s: HTTP %d: %s", t.name, res.Status, res.ProblemCode())
	}
	return created.ID, created.HostRevision, nil
}

// markMounted writes <id>/.paddock-mount with the host revision into the volume backup-local-dev as uid 999, in the
// pgBackRest image of the stack (it has a shell; the server image has none).
func markMounted(ctx context.Context, id string, rev int) error {
	image := stack.Env("PADDOCK_PGBACKREST_IMAGE", "paddock-pgbackrest:dev")
	_, err := stack.Docker(ctx, nil, "run", "--rm", "-u", "999:999", "-v", stack.Project()+"_backup-local-dev:/t",
		"-e", "ID="+id, "-e", "REV="+strconv.Itoa(rev), "--entrypoint", "sh", image, "-c",
		`mkdir -p "/t/$ID" && printf '%s\n' "$REV" >"/t/$ID/.paddock-mount"`)
	if err != nil {
		return fmt.Errorf("mark backup target %s mounted: %w", id, err)
	}
	return nil
}
