package selfservice

import (
	"github.com/phischl/paddock-mdm/agent/internal/desktop"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// noticeTexts are the notification texts by language, outcome and action; the application and the reason are
// appended as plain arguments of notify-send, never interpreted.
var noticeTexts = map[string]map[string]map[string]string{
	desktop.English: {
		protocol.SelfServiceSucceeded: {protocol.SelfServiceInstall: "Installed: ", protocol.SelfServiceRemove: "Removed: ",
			protocol.SelfServiceUpdate: "Updated: "},
		protocol.SelfServiceFailed: {protocol.SelfServiceInstall: "Installation failed: ", protocol.SelfServiceRemove: "Removal failed: ",
			protocol.SelfServiceUpdate: "Update failed: "},
		protocol.SelfServiceRefused: {protocol.SelfServiceInstall: "Installation refused: ", protocol.SelfServiceRemove: "Removal refused: ",
			protocol.SelfServiceUpdate: "Update refused: "},
	},
	desktop.German: {
		protocol.SelfServiceSucceeded: {protocol.SelfServiceInstall: "Installiert: ", protocol.SelfServiceRemove: "Entfernt: ",
			protocol.SelfServiceUpdate: "Aktualisiert: "},
		protocol.SelfServiceFailed: {protocol.SelfServiceInstall: "Installation fehlgeschlagen: ",
			protocol.SelfServiceRemove: "Entfernen fehlgeschlagen: ", protocol.SelfServiceUpdate: "Aktualisierung fehlgeschlagen: "},
		protocol.SelfServiceRefused: {protocol.SelfServiceInstall: "Installation abgelehnt: ", protocol.SelfServiceRemove: "Entfernen abgelehnt: ",
			protocol.SelfServiceUpdate: "Aktualisierung abgelehnt: "},
	},
}

// notice is the summary and body of the notification of a finished operation.
func notice(lang string, op *operation, outcome, reason string) (summary, body string) {
	texts, ok := noticeTexts[lang]
	if !ok {
		texts = noticeTexts[desktop.English]
	}
	name := op.pkg.Package
	if op.pkg.FlatpakRef != "" {
		name = op.pkg.FlatpakRef
	}
	body = texts[outcome][op.action] + name
	if reason != "" {
		body += " (" + reason + ")"
	}
	return "Paddock Self-Service", body
}
