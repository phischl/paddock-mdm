package encrypt

import (
	"embed"
	"io/fs"
)

//go:embed dracut/module-setup.sh dracut/paddock-encrypt-init.sh dracut/paddock-encrypt-init.service
var dracutModule embed.FS

// Module is the dracut module of the init step (plan M8e §6.4), rooted at its directory: what Preparer.Module and
// WriteModule take.
func Module() fs.FS {
	// fs.Sub fails only for an invalid path; "dracut" is a constant valid one.
	sub, _ := fs.Sub(dracutModule, "dracut")
	return sub
}
