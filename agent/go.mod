module github.com/phischl/paddock-mdm/agent

go 1.27.0

toolchain go1.27.2

require (
	aead.dev/minisign v0.3.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/phischl/paddock-mdm/pkg v0.0.0
)

require (
	github.com/gowebpki/jcs v1.0.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/phischl/paddock-mdm/pkg => ../pkg
