package diagnostics

import (
	"strings"
	"unicode"

	"github.com/phischl/paddock-mdm/agent/internal/desktop"
)

var markup = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// Notice is the desktop notification of a collection in language lang (desktop.German or English) with the
// administrator's reason (ADR 0048 decision 6; the administrator's name is not shown).
func Notice(lang, reason string) (summary, body string) {
	reason = strings.Join(strings.FieldsFunc(reason, unicode.IsControl), " ")
	// Notification servers render a subset of markup in the body: the reason must not become a link or break it.
	reason = markup.Replace(reason)
	if lang == desktop.German {
		return "Paddock: Diagnosedaten erfasst",
			"Paddock hat für Ihre Administration Diagnosedaten von diesem Gerät erfasst. Grund: " + reason +
				". Erfasst wurden: die eigenen Protokolle und die Konfiguration von Paddock, keine persönlichen Dateien."
	}
	return "Paddock: diagnostic data collected",
		"Paddock collected diagnostic data from this device for your administrator. Reason: " + reason +
			". What was collected: Paddock's own logs and configuration, no personal files."
}
