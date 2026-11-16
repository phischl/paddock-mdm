package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

var (
	sqlcParam        = regexp.MustCompile(`sqlc\.n?arg\((\w+)\)|@(\w+)`)
	insertTarget     = regexp.MustCompile(`(?i)^INSERT\s+INTO\s+(\w+)`)
	onConflict       = regexp.MustCompile(`(?i)\bON\s+CONFLICT\b\s*(\(([^)]*)\))?\s*(ON\s+CONSTRAINT\b)?`)
	selectKeyword    = regexp.MustCompile(`(?i)select`)
	deviceKeyedMatch = regexp.MustCompile(`(?i)\bdevice_id\s*=\s*@`)
	orKeyword        = regexp.MustCompile(`(?i)\bOR\b`)
	lineComment      = regexp.MustCompile(`--[^\n]*`)
	blockComment     = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// deviceKeyed reports whether sql, without comments, compares device_id with a parameter in a condition that every
// row must meet: no OR at the parenthesis level of the comparison, so (device_id = @a OR …) does not count, while
// device_id = @a AND (x OR y) does.
func deviceKeyed(sql string) bool {
	text := blockComment.ReplaceAllString(lineComment.ReplaceAllString(sql, ""), "")
	for _, m := range deviceKeyedMatch.FindAllStringIndex(text, -1) {
		if !orKeyword.MatchString(levelText(text, m[0])) {
			return true
		}
	}
	return false
}

// levelText returns the text of the innermost parenthesized group of sql around position pos, or all of sql at the top
// level, with every nested group inside it blanked out.
func levelText(sql string, pos int) string {
	start, depth := 0, 0
	for i := pos - 1; i >= 0; i-- {
		switch sql[i] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				start = i + 1
				i = -1
				continue
			}
			depth--
		}
	}
	var b strings.Builder
	depth = 0
	for i := start; i < len(sql); i++ {
		c := sql[i]
		if c == '(' {
			depth++
		}
		if c == ')' && depth == 0 {
			break
		}
		if depth == 0 {
			b.WriteByte(c)
		}
		if c == ')' {
			depth--
		}
	}
	return b.String()
}

// positional rewrites the sqlc parameters of a query file's SQL (@name, sqlc.arg(name), sqlc.narg(name)) to $1, $2, …
// in order of first use, as sqlc generates them, so PostgreSQL can plan the text.
func positional(sql string) string {
	index := map[string]int{}
	return sqlcParam.ReplaceAllStringFunc(sql, func(m string) string {
		sub := sqlcParam.FindStringSubmatch(m)
		name := sub[1] + sub[2]
		if _, ok := index[name]; !ok {
			index[name] = len(index) + 1
		}
		return "$" + strconv.Itoa(index[name])
	})
}

// admitInsert checks rule (a) of ADR 0055 amendment 2026-11-16 (3) decision 11: the SQL is an INSERT INTO … without
// SELECT, and an ON CONFLICT names the key columns of a unique, non-partial index of the target table. A bare ON
// CONFLICT DO NOTHING passes: its arbiters are all unique indexes of the table, so it reads no more than one.
func admitInsert(ctx context.Context, tx pgx.Tx, sql string) error {
	text := strings.TrimSpace(sql)
	m := insertTarget.FindStringSubmatch(text)
	if m == nil {
		return errors.New("not an INSERT INTO")
	}
	if selectKeyword.MatchString(text) {
		return errors.New("an INSERT with SELECT in its text")
	}
	c := onConflict.FindStringSubmatch(text)
	if c == nil || (c[1] == "" && c[3] == "") {
		return nil
	}
	if c[3] != "" {
		return errors.New("ON CONFLICT ON CONSTRAINT, not a column list")
	}
	var want []string
	for _, col := range strings.Split(c[2], ",") {
		want = append(want, strings.TrimSpace(col))
	}
	slices.Sort(want)
	rows, err := tx.Query(ctx, "SELECT i.indexrelid::regclass::text, "+
		"(SELECT array_agg(pg_get_indexdef(i.indexrelid, k, true)) FROM generate_series(1, i.indnkeyatts) k) "+
		"FROM pg_index i WHERE i.indrelid = $1::regclass AND i.indisunique AND i.indpred IS NULL", m[1])
	if err != nil {
		return fmt.Errorf("unique indexes of %s: %w", m[1], err)
	}
	type unique struct {
		name string
		cols []string
	}
	indexes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (unique, error) {
		var u unique
		err := r.Scan(&u.name, &u.cols)
		return u, err
	})
	if err != nil {
		return fmt.Errorf("unique indexes of %s: %w", m[1], err)
	}
	for _, u := range indexes {
		slices.Sort(u.cols)
		if slices.Equal(u.cols, want) {
			return nil
		}
	}
	return fmt.Errorf("ON CONFLICT (%s) matches no unique index of %s", c[2], m[1])
}

// admitDeviceKeyed checks rule (b) of ADR 0055 amendment 2026-11-16 (3) decision 11: the SQL compares device_id with
// a parameter outside any OR, and no relation of its generic plan has an index led by organization_id whose second
// key column is not device_id. It returns the offending indexes.
func admitDeviceKeyed(ctx context.Context, tx pgx.Tx, sql string) error {
	if !deviceKeyed(sql) {
		return errors.New("compares no device_id with a parameter in a condition every row meets")
	}
	// pgx demands a value for every $n even in the simple protocol; EXPLAIN (GENERIC_PLAN) takes none, so the text goes
	// to the server unchanged.
	results, err := tx.Conn().PgConn().Exec(ctx, "EXPLAIN (GENERIC_PLAN, FORMAT JSON) "+positional(sql)).ReadAll()
	if err != nil {
		return fmt.Errorf("EXPLAIN: %w", err)
	}
	if len(results) != 1 || len(results[0].Rows) != 1 {
		return fmt.Errorf("EXPLAIN: %d results", len(results))
	}
	raw := results[0].Rows[0][0]
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		return fmt.Errorf("EXPLAIN: %s: %w", raw, err)
	}
	relations := planRelations(plan, nil)
	if len(relations) == 0 {
		return fmt.Errorf("no relation in the plan %s", raw)
	}
	var offending []string
	for _, rel := range relations {
		rows, err := tx.Query(ctx, "SELECT i.indexrelid::regclass::text FROM pg_index i "+
			"LEFT JOIN pg_attribute o ON o.attrelid = i.indrelid AND o.attname = 'organization_id' "+
			"LEFT JOIN pg_attribute d ON d.attrelid = i.indrelid AND d.attname = 'device_id' "+
			"WHERE i.indrelid = $1::regclass AND i.indkey[0] = o.attnum "+
			"AND NOT coalesce(i.indnkeyatts >= 2 AND i.indkey[1] = d.attnum, false) ORDER BY 1", rel)
		if err != nil {
			return fmt.Errorf("indexes of %s: %w", rel, err)
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("indexes of %s: %w", rel, err)
		}
		offending = append(offending, names...)
	}
	if len(offending) > 0 {
		return fmt.Errorf("indexes led by organization_id without device_id second: %s", strings.Join(offending, ", "))
	}
	return nil
}

// planRelations collects the distinct "Relation Name" values of an EXPLAIN (FORMAT JSON) plan, subplans included.
func planRelations(node any, seen []string) []string {
	switch n := node.(type) {
	case map[string]any:
		if rel, ok := n["Relation Name"].(string); ok && !slices.Contains(seen, rel) {
			seen = append(seen, rel)
		}
		for _, v := range n {
			seen = planRelations(v, seen)
		}
	case []any:
		for _, v := range n {
			seen = planRelations(v, seen)
		}
	}
	return seen
}

// TestIngestViewAdmissionRule (ADR 0055 amendment 2026-11-16 (3) decisions 11 and 12): every name the statement-cache
// view caches passes rule (a), an insert, or rule (b), device-keyed without an index led by organization_id that lacks
// device_id in second place, checked against its SQL in the query files and the migrated schema. Primary-key access
// alone admits nothing: under statistics that missed a small organization, a generic plan takes such an index instead.
func TestIngestViewAdmissionRule(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pool, err := db.NewOrgPool(ctx, sharedPaddock(t).Worker, db.Options{ApplicationName: "paddock-test-admission", MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	queries := pgstoreQueries(t)

	for _, name := range allowListedNames(t) {
		t.Run(name, func(t *testing.T) {
			sql, ok := queries[name]
			if !ok {
				t.Fatalf("%s: no query of that name in server/internal/adapters/postgres/queries", name)
			}
			err := db.InOrgTx(pool, orgCtx(f.orgA), func(tx pgx.Tx) error {
				errA := admitInsert(ctx, tx, sql)
				if errA == nil {
					return errRollback
				}
				errB := admitDeviceKeyed(ctx, tx, sql)
				if errB == nil {
					return errRollback
				}
				return fmt.Errorf("rule (a): %v; rule (b): %v", errA, errB)
			})
			if !errors.Is(err, errRollback) {
				t.Errorf("%s may not be cached by the view: %v", name, err)
			}
		})
	}

	// The checks themselves reject what the rule excludes: an organization index without device_id in second place on a
	// table of a device-keyed statement, an insert with SELECT and a conflict target that is no unique index.
	t.Run("rejects", func(t *testing.T) {
		super, err := pgx.Connect(ctx, sharedPaddock(t).Super)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = super.Close(ctx) })
		tx, err := super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, s := range []string{
			"CREATE SCHEMA admission_mutation",
			"CREATE TABLE admission_mutation.device_event_seen (LIKE public.device_event_seen INCLUDING INDEXES)",
			"SET LOCAL search_path = admission_mutation, public",
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		maxSeen := queries["MaxDeviceEventSeenBefore"]
		if err := admitDeviceKeyed(ctx, tx, maxSeen); err != nil {
			t.Fatalf("MaxDeviceEventSeenBefore on the copied schema: %v", err)
		}
		if _, err := tx.Exec(ctx, "CREATE INDEX ON device_event_seen (organization_id, event_seq)"); err != nil {
			t.Fatal(err)
		}
		if err := admitDeviceKeyed(ctx, tx, maxSeen); err == nil || !strings.Contains(err.Error(), "device_event_seen_organization_id_event_seq_idx") {
			t.Errorf("MaxDeviceEventSeenBefore with an index on (organization_id, event_seq): %v, want that index named", err)
		}
		for sql, want := range map[string]string{
			"INSERT INTO device_user_seen (organization_id, device_id, username, last_seen_at) VALUES (@a, @b, @c, @d) " +
				"ON CONFLICT (username) DO NOTHING": "matches no unique index",
			"INSERT INTO outbox (organization_id, subject, msg_id, payload) SELECT organization_id, 'x', 'y', '{}' FROM device": "SELECT",
			"UPDATE device SET hostname = @hostname WHERE id = @id":                                                             "not an INSERT",
		} {
			if err := admitInsert(ctx, tx, sql); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("admitInsert(%q) = %v, want an error with %q", sql, err, want)
			}
		}
		if err := admitDeviceKeyed(ctx, tx, "SELECT hostname FROM device WHERE id = @id"); err == nil {
			t.Error("admitDeviceKeyed accepts a statement without device_id = @…")
		}
	})
}

// TestDeviceKeyed: rule (b)'s text check counts a device_id comparison only where every row must meet it.
func TestDeviceKeyed(t *testing.T) {
	for sql, want := range map[string]bool{
		"DELETE FROM device_event_dropped WHERE device_id = @device_id":                                  true,
		"DELETE FROM device_event_seen WHERE device_id = @device_id AND (received_at IS NULL OR x < @b)": true,
		"SELECT coalesce((SELECT s FROM t WHERE device_id = @device_id AND (a OR b) LIMIT 1), 0)":        true,
		"DELETE FROM t WHERE device_id = @device_id OR organization_id = @org":                           false,
		"DELETE FROM t WHERE (device_id = @device_id OR true) AND x = 1":                                 false,
		"SELECT 1 FROM device WHERE id = @id -- device_id = @device_id":                                  false,
		"SELECT 1 FROM device WHERE id = @id /* device_id = @device_id */":                               false,
		"SELECT 1 FROM device WHERE id = @id":                                                            false,
	} {
		if got := deviceKeyed(sql); got != want {
			t.Errorf("deviceKeyed(%q) = %v, want %v", sql, got, want)
		}
	}
}
