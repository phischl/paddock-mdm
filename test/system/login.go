package system

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/portal"
)

// Login helpers of the identity gates (plan M3b §6). They reproduce the techniques of PoC M1 (test/poc/m1): pamtester
// over SSH with a pseudo terminal answering the PAM conversation, the GDM greeter and the GNOME lock screen through
// the VirtualBox keyboard with screenshots, and the device code approved like a user on a second device.

// pamOpts answer a PAM conversation.
type pamOpts struct {
	pin, password string
	// approve is called with the device code Himmelblau shows; nil never approves (the attempt fails once the code
	// expires, about 60 s).
	approve func(code string) error
	timeout time.Duration
}

// pamPrompts map a pending prompt (lower case) to the answer: PIN prompts first, as in PoC M1.
var pamPrompts = []struct {
	re     *regexp.Regexp
	answer string // "pin" or "password"
}{
	{regexp.MustCompile(`(confirm|repeat|again).*pin.*[:>]\s*$`), "pin"},
	{regexp.MustCompile(`(new|set up|setup|choose|create|enroll).*pin.*[:>]\s*$`), "pin"},
	{regexp.MustCompile(`pin.*[:>]\s*$`), "pin"},
	{regexp.MustCompile(`password.*[:>]\s*$`), "password"},
}

// deviceCode finds the user code in Himmelblau's device flow message (also the ?code= of the verification URL).
var deviceCode = regexp.MustCompile(`(?i)(?:code=|code[:\s]+)(\d{6,})`)

// PAM runs `pamtester -v <service> <user> <ops>` in the guest and answers the conversation. It returns pamtester's
// exit code (-1 if it did not finish) and the transcript, which never contains the answers.
func (v *VM) PAM(t *testing.T, service, user string, ops []string, o pamOpts) (int, string) {
	t.Helper()
	if o.timeout == 0 {
		o.timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	args := append(v.sshArgs(), "-tt", "-p", v.port, "paddock@127.0.0.1",
		fmt.Sprintf("sudo pamtester -v %s %s %s; echo PAMTESTER_EXIT=$?", service, user, strings.Join(ops, " ")))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	chunks := make(chan string)
	go func() {
		defer close(chunks)
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunks <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	var transcript strings.Builder
	approvals := make(chan error, 1)
	all, line, approved, exit := "", "", false, -1
	for chunk := range chunks {
		all += chunk
		line += chunk
		for {
			done, rest, ok := strings.Cut(line, "\n")
			if !ok {
				break
			}
			line = rest
			done = strings.TrimRight(done, "\r")
			fmt.Fprintf(&transcript, "%s vm: %s\n", time.Now().UTC().Format("15:04:05.000"), done)
			if m := regexp.MustCompile(`PAMTESTER_EXIT=(\d+)`).FindStringSubmatch(done); m != nil {
				exit, _ = strconv.Atoi(m[1])
			}
		}
		if m := deviceCode.FindStringSubmatch(all); m != nil && !approved {
			approved = true
			fmt.Fprintf(&transcript, "%s host: device code %s\n", time.Now().UTC().Format("15:04:05.000"), m[1])
			if o.approve != nil {
				go func() { approvals <- o.approve(m[1]) }()
			}
		}
		pending := strings.ToLower(strings.TrimSpace(line))
		for _, p := range pamPrompts {
			if pending == "" || !p.re.MatchString(pending) {
				continue
			}
			answer := o.pin
			if p.answer == "password" {
				answer = o.password
			}
			fmt.Fprintf(&transcript, "%s vm: %s <%s sent>\n", time.Now().UTC().Format("15:04:05.000"), strings.TrimSpace(line), p.answer)
			_, _ = io.WriteString(stdin, answer+"\n")
			line = ""
			break
		}
	}
	_ = cmd.Wait()
	select {
	case err := <-approvals:
		if err != nil {
			fmt.Fprintf(&transcript, "host: approval: %v\n", err)
		}
	default:
	}
	return exit, transcript.String()
}

// Session is a logind session of the guest.
type Session struct {
	ID, Name, Class, Seat, Type, State string
	LockedHint                         bool
}

// Sessions lists the guest's logind sessions. A session that ends while it is listed is left out.
func (v *VM) Sessions() []Session {
	v.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := v.SSH(ctx, nil, `for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
		loginctl show-session "$s" -p Id -p Name -p Class -p Seat -p Type -p State -p LockedHint 2>/dev/null && echo; done`)
	if err != nil {
		v.t.Logf("%s: sessions: %v: %s", v.Name, err, out)
		return nil
	}
	var list []Session
	for _, block := range strings.Split(out, "\n\n") {
		var s Session
		for _, kv := range strings.Split(strings.TrimSpace(block), "\n") {
			k, val, _ := strings.Cut(kv, "=")
			switch k {
			case "Id":
				s.ID = val
			case "Name":
				s.Name = val
			case "Class":
				s.Class = val
			case "Seat":
				s.Seat = val
			case "Type":
				s.Type = val
			case "State":
				s.State = val
			case "LockedHint":
				s.LockedHint = val == "yes"
			}
		}
		if s.ID != "" {
			list = append(list, s)
		}
	}
	return list
}

// UserSessions returns the sessions of class user of name. Himmelblau lists the users of its domain by their short
// name, so name@domain also matches the short name.
func (v *VM) UserSessions(name string) []Session {
	short, _, _ := strings.Cut(name, "@")
	var out []Session
	for _, s := range v.Sessions() {
		if (s.Name == name || s.Name == short) && strings.HasPrefix(s.Class, "user") {
			out = append(out, s)
		}
	}
	return out
}

// Scancodes of the US keyboard (set 1, make and break).
var (
	keyEnter = []string{"1c", "9c"}
	keyTab   = []string{"0f", "8f"}
	keySpace = []string{"39", "b9"}
)

// Key sends scancodes to the VM's keyboard.
func (v *VM) Key(codes ...string) {
	v.t.Helper()
	if out, err := run(context.Background(), "VBoxManage", append([]string{"controlvm", v.Name, "keyboardputscancode"}, codes...)...); err != nil {
		v.t.Fatalf("keyboard %v: %v: %s", codes, err, out)
	}
}

// Type types text on the VM's keyboard (US layout, as the guests are configured) followed by Enter.
func (v *VM) Type(text string) {
	v.t.Helper()
	if out, err := run(context.Background(), "VBoxManage", "controlvm", v.Name, "keyboardputstring", text); err != nil {
		v.t.Fatalf("keyboard: %v: %s", err, out)
	}
	v.Key(keyEnter...)
}

// Shot saves a screenshot of the VM console as evidence (bin/system-evidence/<vm>/<test>-<name>.png) and returns its
// path.
func (v *VM) Shot(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(v.dir, "..", "..", "..", "bin", "system-evidence", v.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"-"+name+".png")
	if out, err := run(context.Background(), "VBoxManage", "controlvm", v.Name, "screenshotpng", path); err != nil {
		t.Logf("screenshot %s: %v: %s", name, err, out)
	}
	return path
}

// authentikSQL runs a query in Authentik's database (test-only access) and returns its rows.
func authentikSQL(ctx context.Context, query string) (string, error) {
	out, err := portal.Compose(ctx, "exec", "-T", "authentik-postgres", "psql", "-U", "authentik", "-d", "authentik", "-tAc", query)
	return strings.TrimSpace(out), err
}

// paddockSQL runs a query in Paddock's database as the superuser (test-only access).
func paddockSQL(ctx context.Context, query string) (string, error) {
	out, err := portal.Compose(ctx, "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "paddock", "-tAc", query)
	return strings.TrimSpace(out), err
}

// pendingUserCode returns the user code of the newest unapproved device authorization of the organization's device
// application with an ID above after: the code the GDM greeter shows. Reading it from Authentik's database stands in
// for reading the greeter screen.
func pendingUserCode(t *testing.T, slug string, after int) (code string, id int) {
	t.Helper()
	query := fmt.Sprintf(`SELECT t.id || ' ' || t.user_code FROM authentik_providers_oauth2_devicetoken t
		JOIN authentik_core_provider p ON p.id = t.provider_id
		WHERE p.name = 'paddock-device-%s' AND t.user_id IS NULL AND t.id > %d ORDER BY t.id DESC LIMIT 1`, slug, after)
	Until(t, "device code shown", 2*time.Minute, 2*time.Second, nil, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := authentikSQL(ctx, query)
		if err != nil {
			t.Logf("authentik database: %v: %s", err, out)
			return false
		}
		f := strings.Fields(out)
		if len(f) != 2 {
			return false
		}
		id, _ = strconv.Atoi(f[0])
		code = f[1]
		return true
	})
	return code, id
}

// lastDeviceTokenID is the highest device authorization ID so far (pendingUserCode looks only above it).
func lastDeviceTokenID(t *testing.T) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := authentikSQL(ctx, "SELECT coalesce(max(id), 0) FROM authentik_providers_oauth2_devicetoken")
	if err != nil {
		t.Fatalf("authentik database: %v: %s", err, out)
	}
	id, _ := strconv.Atoi(out)
	return id
}

// guestScript runs a shell script as root in the guest in a transient unit after delay, e.g. while the network is
// cut; secret is passed in /root/systest-secret (removed by the script's caller) and the output lands in log.
func (v *VM) guestScript(script, secret, log string, delay time.Duration) {
	v.t.Helper()
	v.MustIn([]byte(script), "sudo tee /root/systest.sh >/dev/null && sudo chmod 700 /root/systest.sh")
	v.MustIn([]byte(secret), "sudo tee /root/systest-secret >/dev/null && sudo chmod 600 /root/systest-secret")
	v.Must(fmt.Sprintf("sudo rm -f %s; sudo systemd-run --quiet --unit systest-%d --on-active=%d /bin/bash -c '/root/systest.sh >%s 2>&1; rm -f /root/systest-secret'",
		log, time.Now().UnixNano(), int(delay.Seconds()), log))
}
