// Package server holds code generation directives for the server module (run `make gen`).
package server

//go:generate go tool sqlc generate
//go:generate go tool oapi-codegen -config internal/transport/http/admin/adminapi/oapi-codegen.yaml ../api/openapi/admin.yaml
//go:generate go run ./cmd/mcpgen -spec ../api/openapi/admin.yaml -out ../pkg/mcpcatalog/catalog.gen.go
//go:generate go run ./cmd/mcpgen -spec ../api/openapi/admin.yaml -skill ../skills/operate-paddock/references/tools.md
//go:generate go run ./internal/domain/audit/gendoc ../docs/compliance/audit-codes.md
//go:generate go run ./internal/domain/audit/gendoc web/src/lib/auditCodes.gen.ts
