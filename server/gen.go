// Package server holds code generation directives for the server module (run `make gen`).
package server

//go:generate go tool sqlc generate
//go:generate go run ./internal/domain/audit/gendoc ../docs/compliance/audit-codes.md
