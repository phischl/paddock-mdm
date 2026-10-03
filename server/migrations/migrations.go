// Package migrations embeds the forward-only SQL migrations of both databases.
package migrations

import "embed"

// Paddock holds the migrations of database paddock (directory paddock/).
//
//go:embed paddock/*.sql
var Paddock embed.FS

// Audit holds the migrations of database paddock_audit (directory audit/).
//
//go:embed audit/*.sql
var Audit embed.FS
