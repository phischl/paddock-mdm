package app

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// accessReviewColumns are the columns of the CSV export: one file for every section, told apart by section. A row
// fills the columns that apply to its section and leaves the others empty.
var accessReviewColumns = []string{
	"section", "at", "code", "username", "display_name", "role", "actor", "target", "detail", "first_seen_at",
	"last_login_at", "disabled", "prefix", "created_by", "created_at", "expires_at", "last_used_at", "revoked_at",
	"revoked_by", "count",
}

// csvRow is one row by column name.
type csvRow map[string]string

// csvSafe neutralizes a cell a spreadsheet would run as a formula (OWASP CSV injection): a cell that starts with =, +,
// -, @, a tab, a carriage return or a line feed gets a leading apostrophe.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}

func renderCSV(rows []csvRow) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(accessReviewColumns); err != nil {
		return nil, fmt.Errorf("write access review csv: %w", err)
	}
	for _, r := range rows {
		cells := make([]string, len(accessReviewColumns))
		for i, c := range accessReviewColumns {
			cells[i] = csvSafe(r[c])
		}
		if err := w.Write(cells); err != nil {
			return nil, fmt.Errorf("write access review csv: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("write access review csv: %w", err)
	}
	return buf.Bytes(), nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func tsp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ts(*t)
}

// detail renders parameters as sorted key=value pairs.
func detail(params map[string]any) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%v", k, params[k])
	}
	return strings.Join(parts, " ")
}

// sectionRows appends the rows of a section and, when it was capped, a <name>_truncated row with the total.
func sectionRows[T any](rows []csvRow, name string, s Section[T], row func(T) csvRow) []csvRow {
	for _, it := range s.Items {
		r := row(it)
		r["section"] = name
		rows = append(rows, r)
	}
	if s.Total > len(s.Items) {
		rows = append(rows, csvRow{"section": name + "_truncated", "count": strconv.Itoa(s.Total)})
	}
	return rows
}

func roleRows(rows []csvRow, roles []RoleMembers) []csvRow {
	for _, r := range roles {
		if len(r.Members.Items) == 0 && r.Members.Total == 0 {
			rows = append(rows, csvRow{"section": "role_members", "role": r.Role, "at": tsp(r.SnapshotTakenAt), "count": "0"})
			continue
		}
		rows = sectionRows(rows, "role_members", r.Members, func(m RoleMember) csvRow {
			return csvRow{"role": r.Role, "username": m.Username, "detail": "authentik_pk=" + m.AuthentikPK,
				"first_seen_at": ts(m.FirstSeenAt), "at": tsp(r.SnapshotTakenAt)}
		})
	}
	return rows
}

func roleChangeRows(rows []csvRow, s Section[RoleChange]) []csvRow {
	return sectionRows(rows, "role_changes", s, func(c RoleChange) csvRow {
		return csvRow{"at": ts(c.At), "code": c.Code, "username": c.Username, "role": c.Role, "actor": c.Actor}
	})
}

func (r Report) csv() ([]byte, error) {
	rows := []csvRow{{"section": "report", "at": ts(r.GeneratedAt), "detail": "from=" + ts(r.Period.From) + " to=" + ts(r.Period.To)}}
	rows = roleRows(rows, r.Roles)
	rows = roleChangeRows(rows, r.RoleChanges)
	rows = sectionRows(rows, "accounts", r.Accounts, func(a ReviewAccount) csvRow {
		return csvRow{"username": a.Username, "display_name": a.DisplayName, "role": a.Role,
			"last_login_at": tsp(a.LastLoginAt), "disabled": strconv.FormatBool(a.Disabled)}
	})
	rows = sectionRows(rows, "api_tokens", r.APITokens, func(t ReviewToken) csvRow {
		by := ""
		if t.RevokedBy != nil {
			by = *t.RevokedBy
		}
		return csvRow{"display_name": t.Name, "role": t.Role, "prefix": t.Prefix, "created_by": t.CreatedBy,
			"created_at": ts(t.CreatedAt), "expires_at": ts(t.ExpiresAt), "last_used_at": tsp(t.LastUsedAt),
			"revoked_at": tsp(t.RevokedAt), "revoked_by": by}
	})
	rows = append(rows,
		csvRow{"section": "token_denials", "count": strconv.Itoa(r.TokenDenials)},
		csvRow{"section": "step_up_succeeded", "count": strconv.Itoa(r.StepUp.Succeeded)},
		csvRow{"section": "step_up_failed", "count": strconv.Itoa(r.StepUp.Failed)})
	rows = sectionRows(rows, "reveals", r.Reveals, func(v Reveal) csvRow {
		return csvRow{"at": ts(v.At), "code": v.Code, "actor": v.Actor, "target": v.DeviceHostname, "detail": detail(v.Params)}
	})
	rows = sectionRows(rows, "sessions_revoked", r.SessionsRevoked, func(s SessionRevocation) csvRow {
		return csvRow{"at": ts(s.At), "username": s.Username, "detail": "reason=" + s.Reason}
	})
	for _, name := range r.BreakGlassAccounts {
		rows = append(rows, csvRow{"section": "break_glass_accounts", "username": name})
	}
	rows = sectionRows(rows, "destructive", r.Destructive, func(d DestructiveAction) csvRow {
		return csvRow{"at": ts(d.At), "code": d.Code, "actor": d.Actor, "target": d.Target}
	})
	return renderCSV(rows)
}

func (r PlatformReport) csv() ([]byte, error) {
	rows := []csvRow{{"section": "report", "at": ts(r.GeneratedAt), "detail": "from=" + ts(r.Period.From) + " to=" + ts(r.Period.To)}}
	rows = roleRows(rows, r.Roles)
	rows = sectionRows(rows, "administrators", r.Administrators, func(a PlatformAdministrator) csvRow {
		return csvRow{"username": a.Username, "display_name": a.DisplayName, "last_login_at": tsp(a.LastLoginAt)}
	})
	rows = roleChangeRows(rows, r.RoleChanges)
	rows = sectionRows(rows, "events", r.Events, func(e PlatformEvent) csvRow {
		return csvRow{"at": ts(e.At), "code": e.Code, "actor": e.Actor, "target": e.Target}
	})
	rows = sectionRows(rows, "organizations_created", r.OrganizationsCreated, func(o CreatedOrganization) csvRow {
		return csvRow{"username": o.Slug, "display_name": o.Name, "created_at": ts(o.CreatedAt)}
	})
	return renderCSV(rows)
}
