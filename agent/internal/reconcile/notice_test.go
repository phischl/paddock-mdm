package reconcile_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// TestLoginNotice (plan M4a decision 19): the notice reaches GDM (dconf keyfile and dconf update), the text
// consoles (/etc/issue.d) and SSH (banner file, sshd drop-in, reload); local changes are restored, a new text
// replaces the files and an empty one removes them.
func TestLoginNotice(t *testing.T) {
	ctx := context.Background()
	sys, l, events := loginFixture(t)
	for _, p := range []string{"gdm3", "dconf-cli", "openssh-server"} {
		sys.Packages[p] = true
	}
	spec := loginSpec()
	spec.Notice = "Managed by Acme. Don't misuse it.\nPath C:\\tmp\tend"
	l.Apply(ctx, loginResource(t, spec))
	takeEvents(events)
	sys.TakeCalls()

	// The files exist already from the first apply; check their content and a change.
	gdm := string(sys.Files[reconcile.NoticeGDM].Data)
	if !strings.Contains(gdm, "[org/gnome/login-screen]\nbanner-message-enable=true\n") ||
		!strings.Contains(gdm, `banner-message-text='Managed by Acme. Don\'t misuse it.\nPath C:\\tmp\tend'`) {
		t.Fatalf("GDM keyfile\n%s", gdm)
	}
	if got := string(sys.Files[reconcile.NoticeIssue].Data); got != "Managed by Acme. Don't misuse it.\nPath C:\\\\tmp\tend\n\n" {
		t.Fatalf("issue %q", got)
	}
	if got := string(sys.Files[reconcile.NoticeSSH].Data); got != spec.Notice+"\n" ||
		!strings.HasSuffix(string(sys.Files[reconcile.NoticeSSHConfig].Data), "Banner /etc/paddock/notice\n") {
		t.Fatalf("SSH banner %q, config %q", got, sys.Files[reconcile.NoticeSSHConfig].Data)
	}

	r := loginResource(t, spec)
	if changes, err := l.Plan(ctx, r); err != nil || len(changes) != 0 {
		t.Fatalf("plan after apply: %v %v", changes, err)
	}
	sys.Files[reconcile.NoticeIssue].Data = []byte("hacked\n")
	if changes, _ := l.Plan(ctx, r); !slices.Equal(changes, []string{"notice " + reconcile.NoticeIssue}) {
		t.Fatalf("drift plan %v", changes)
	}
	if res := l.Apply(ctx, r); res.Status != reconcile.Changed || !strings.HasPrefix(string(sys.Files[reconcile.NoticeIssue].Data), "Managed by Acme") {
		t.Fatalf("drift apply %+v", res)
	}
	if calls := sys.TakeCalls(); slices.Contains(calls, "dconf update") || slices.Contains(calls, "systemctl try-reload-or-restart ssh.service") {
		t.Fatalf("an issue change compiled dconf or reloaded ssh: %v", calls)
	}
	if got := takeEvents(events); len(got) != 1 || got[0].typ != protocol.EventLoginApplied || got[0].data != `{"changed":["notice"]}` {
		t.Fatalf("events %v", got)
	}

	spec.Notice = "New text"
	l.Apply(ctx, loginResource(t, spec))
	calls := sys.TakeCalls()
	if !slices.Contains(calls, "dconf update") || !slices.Contains(calls, "systemctl try-reload-or-restart ssh.service") ||
		string(sys.Files[reconcile.NoticeSSH].Data) != "New text\n" {
		t.Fatalf("text change: calls %v", calls)
	}

	spec.Notice = ""
	l.Apply(ctx, loginResource(t, spec))
	for _, p := range []string{reconcile.NoticeGDM, reconcile.NoticeIssue, reconcile.NoticeSSH, reconcile.NoticeSSHConfig} {
		if sys.Files[p] != nil {
			t.Fatalf("%s left after the notice was removed", p)
		}
	}
	if calls := sys.TakeCalls(); !slices.Contains(calls, "dconf update") || !slices.Contains(calls, "systemctl try-reload-or-restart ssh.service") {
		t.Fatalf("removal: calls %v", calls)
	}
}

func TestLoginNoticeWithoutGDMAndSSH(t *testing.T) {
	sys, l, _ := loginFixture(t)
	spec := loginSpec()
	spec.Notice = "Server notice"
	l.Apply(context.Background(), loginResource(t, spec))
	if sys.Files[reconcile.NoticeIssue] == nil || sys.Files[reconcile.NoticeGDM] != nil || sys.Files[reconcile.NoticeSSH] != nil {
		t.Fatal("notice files without GDM and SSH server")
	}
	spec.Notice = "bad\x1b[31m"
	if res := l.Apply(context.Background(), loginResource(t, spec)); res.Status != reconcile.Error {
		t.Fatalf("control characters accepted: %+v", res)
	}
}
