module github.com/paddock-mdm/paddock/test/system

go 1.27.0

toolchain go1.27.1

require (
	aead.dev/minisign v0.3.0
	github.com/google/uuid v1.6.0
	github.com/paddock-mdm/paddock/test/acceptance v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.11.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace (
	github.com/paddock-mdm/paddock/pkg => ../../pkg
	github.com/paddock-mdm/paddock/test/acceptance => ../acceptance
)
