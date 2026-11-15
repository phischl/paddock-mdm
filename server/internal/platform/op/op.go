// Package op names the operation a context belongs to: an admin API operation, an audited action, a worker round or
// queue. Metrics use it as a label (paddock_db_transaction_timeout_total{op}, plan M17 amendment r point 5), so names
// come from closed sets only: operation IDs, action codes, round and queue names.
package op

import "context"

// Unknown is the name of a context without one.
const Unknown = "unknown"

type key struct{}

// With returns ctx naming the operation whose work follows; an inner name replaces an outer one.
func With(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, key{}, name)
}

// From is the operation With set on ctx, Unknown without one.
func From(ctx context.Context) string {
	if name, ok := ctx.Value(key{}).(string); ok && name != "" {
		return name
	}
	return Unknown
}
