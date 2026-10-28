// Package mcpcatalog is the MCP tool catalog generated from the admin API contract api/openapi/admin.yaml by
// server/cmd/mcpgen (`make gen`, ADR 0044 decision 4). Each tool is one admin API operation, named by its
// operationId and classified as read or write. The server enforces from it what an MCP session may call and
// paddockctl offers its exposed tools; operations that always need a step-up are listed but never exposed.
// The package depends on the standard library only.
package mcpcatalog
