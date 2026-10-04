module github.com/paddock-mdm/paddock/agent

go 1.25.0

require (
	aead.dev/minisign v0.3.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/paddock-mdm/paddock/pkg v0.0.0
)

require (
	github.com/gowebpki/jcs v1.0.2 // indirect
	golang.org/x/crypto v0.13.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
)

replace github.com/paddock-mdm/paddock/pkg => ../pkg
