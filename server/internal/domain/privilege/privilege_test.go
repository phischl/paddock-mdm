package privilege

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"pgregory.net/rapid"

	"github.com/paddock-mdm/paddock/pkg/sudoers"
)

var (
	dave     = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	ops      = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	web      = uuid.MustParse("00000000-0000-4000-8000-0000000000a2")
	servers  = uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	laptops  = uuid.MustParse("00000000-0000-4000-8000-0000000000b2")
	pBase    = Profile{ID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Name: "base", Class: ClassNone, RequirePassword: true, TimestampTimeoutMin: 15, Lecture: LectureOnce}
	pNginx   = Profile{ID: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Name: "nginx", Class: ClassRestricted, Commands: []string{"/usr/bin/systemctl restart nginx.service"}, RequirePassword: false, TimestampTimeoutMin: 10, Lecture: LectureNever}
	pLogs    = Profile{ID: uuid.MustParse("00000000-0000-4000-8000-000000000003"), Name: "logs", Class: ClassRestricted, Commands: []string{"/usr/bin/journalctl -u nginx.service", "/usr/bin/systemctl restart nginx.service"}, RequirePassword: true, TimestampTimeoutMin: 5, Lecture: LectureOnce}
	pRoot    = Profile{ID: uuid.MustParse("00000000-0000-4000-8000-000000000004"), Name: "root", Class: ClassFull, RequirePassword: true, TimestampTimeoutMin: 0, Lecture: LectureAlways}
	profiles = []Profile{pBase, pNginx, pLogs, pRoot}
)

func assign(n byte, p Profile, t SubjectType, subject, deviceGroup uuid.UUID) Assignment {
	return Assignment{ID: uuid.UUID{0x10, 15: n}, ProfileID: p.ID, SubjectType: t, SubjectID: subject, DeviceGroupID: deviceGroup}
}

func TestEffective(t *testing.T) {
	global := assign(1, pBase, SubjectGlobal, uuid.Nil, uuid.Nil)
	groupNginx := assign(2, pNginx, SubjectGroup, ops, uuid.Nil)
	groupLogs := assign(3, pLogs, SubjectGroup, web, uuid.Nil)
	userRootOnServers := assign(4, pRoot, SubjectUser, dave, servers)
	all := []Assignment{global, groupNginx, groupLogs, userRootOnServers}

	t.Run("no assignment", func(t *testing.T) {
		e := Effective(Input{UserID: dave, Profiles: profiles})
		if e.Class != ClassNone || e.ReportedClass != ClassNone || len(e.Commands) != 0 || !e.RequirePassword || e.Lecture != LectureAlways {
			t.Fatalf("%+v", e)
		}
		if _, ok, _ := e.SudoEntry("dave@acme.test"); ok {
			t.Fatal("class none has a sudo entry")
		}
	})
	t.Run("global only", func(t *testing.T) {
		e := Effective(Input{UserID: dave, Assignments: all, Profiles: profiles})
		if e.Class != ClassNone || e.TimestampTimeoutMin != 15 || e.Lecture != LectureOnce {
			t.Fatalf("%+v", e)
		}
	})
	t.Run("groups: union of commands, most restrictive scalars, group over global", func(t *testing.T) {
		e := Effective(Input{UserID: dave, UserGroups: []uuid.UUID{ops, web}, DeviceGroups: []uuid.UUID{laptops}, Assignments: all, Profiles: profiles})
		want := []string{"/usr/bin/journalctl -u nginx.service", "/usr/bin/systemctl restart nginx.service"}
		if e.Class != ClassRestricted || !slices.Equal(e.Commands, want) {
			t.Fatalf("class %s commands %v", e.Class, e.Commands)
		}
		if !e.RequirePassword || e.TimestampTimeoutMin != 5 || e.Lecture != LectureOnce {
			t.Fatalf("scalars %v %d %s; want the most restrictive of the two group profiles", e.RequirePassword, e.TimestampTimeoutMin, e.Lecture)
		}
		if e.RootEquivalent || e.ReportedClass != ClassRestricted {
			t.Fatalf("root equivalent %v %v", e.RootEquivalent, e.RootEquivalentCommands)
		}
		// The shared command is derived from both group assignments.
		var from []uuid.UUID
		for _, d := range e.Derivation {
			if d.Kind == DerivedCommand && d.Item == want[1] {
				from = append(from, d.AssignmentID)
			}
		}
		if !slices.Equal(from, []uuid.UUID{groupNginx.ID, groupLogs.ID}) {
			t.Fatalf("derivation of %s: %v", want[1], from)
		}
	})
	t.Run("device group scope and user over group", func(t *testing.T) {
		e := Effective(Input{UserID: dave, UserGroups: []uuid.UUID{ops}, DeviceGroups: []uuid.UUID{servers}, Assignments: all, Profiles: profiles})
		if e.Class != ClassFull || e.ReportedClass != ClassFull {
			t.Fatalf("class %s on a server", e.Class)
		}
		// The user-level profile alone defines the scalars.
		if !e.RequirePassword || e.TimestampTimeoutMin != 0 || e.Lecture != LectureAlways {
			t.Fatalf("scalars %+v", e)
		}
		entry, ok, err := e.SudoEntry("dave@acme.test")
		if err != nil || !ok || entry.Class != sudoers.ClassFull || len(entry.Commands) != 0 || len(entry.ProfileDigest) != 64 {
			t.Fatalf("entry %+v %v %v", entry, ok, err)
		}
	})
	t.Run("assignments of others and unknown profiles", func(t *testing.T) {
		other := assign(9, pRoot, SubjectUser, uuid.New(), uuid.Nil)
		ghost := Assignment{ID: uuid.New(), ProfileID: uuid.New(), SubjectType: SubjectGlobal}
		e := Effective(Input{UserID: dave, Assignments: []Assignment{other, ghost}, Profiles: profiles})
		if e.Class != ClassNone || len(e.Derivation) != 0 {
			t.Fatalf("%+v", e)
		}
	})
}

// TestRootEquivalence is the unit part of gate P2: two restricted profiles that are harmless on their own combine into
// a root-equivalent set; the effective profile is reported as full and names both commands.
func TestRootEquivalence(t *testing.T) {
	copyHelper := Profile{ID: uuid.New(), Name: "deploy helper", Class: ClassRestricted, Lecture: LectureOnce,
		Commands: []string{"/usr/bin/cp /srv/build/helper /opt/tools/helper"}}
	runHelper := Profile{ID: uuid.New(), Name: "run helper", Class: ClassRestricted, Lecture: LectureOnce,
		Commands: []string{"/opt/tools/helper --sync"}}
	for _, p := range []Profile{copyHelper, runHelper} {
		if e := Effective(Input{UserID: dave, Profiles: []Profile{p}, Assignments: []Assignment{assign(1, p, SubjectUser, dave, uuid.Nil)}}); e.RootEquivalent {
			t.Fatalf("%s alone is root-equivalent: %v", p.Name, e.RootEquivalentCommands)
		}
	}
	e := Effective(Input{
		UserID: dave, UserGroups: []uuid.UUID{ops}, Profiles: []Profile{copyHelper, runHelper},
		Assignments: []Assignment{assign(1, copyHelper, SubjectUser, dave, uuid.Nil), assign(2, runHelper, SubjectGroup, ops, uuid.Nil)},
	})
	if !e.RootEquivalent || e.Class != ClassRestricted || e.ReportedClass != ClassFull || len(e.RootEquivalentCommands) != 2 {
		t.Fatalf("combined: %+v", e)
	}
	entry, _, _ := e.SudoEntry("dave@acme.test")
	if !entry.RootEquivalent || entry.Class != sudoers.ClassRestricted || len(entry.Commands) != 2 {
		t.Fatalf("entry %+v: a root-equivalent restricted entry keeps its commands", entry)
	}
}

func TestIsRootEquivalent(t *testing.T) {
	yes := []string{
		"/usr/bin/bash", "/bin/sh -c id", "/usr/bin/apt-get install nginx", "/usr/bin/systemctl edit nginx.service",
		"/usr/bin/systemctl *", "/usr/bin/systemctl", "/usr/bin/vim /etc/hosts", "/usr/bin/chmod", "/usr/bin/cp * /tmp",
		"/usr/bin/tee /etc/sudoers.d/x", "/usr/bin/cp /tmp/x /usr/local/bin/x", "/usr/bin/*", "/usr/bin/docker ps",
		"/sbin/modprobe dummy", "/usr/bin/less /var/log/syslog", "/usr/bin/chown dave /etc/cron.d/job",
	}
	for _, c := range yes {
		if !IsRootEquivalent(c) {
			t.Errorf("%s: not root-equivalent", c)
		}
	}
	no := []string{
		"/usr/bin/systemctl restart nginx.service", "/usr/bin/journalctl -u nginx.service", "/usr/bin/cp /srv/a /srv/b",
		"/usr/bin/tee /var/log/app.log", "/usr/local/bin/backup --now", "/usr/bin/apt-cache policy",
	}
	for _, c := range no {
		if IsRootEquivalent(c) {
			t.Errorf("%s: root-equivalent", c)
		}
	}
	if got := RootEquivalentCommands([]string{"/usr/bin/tee /opt/x/run.sh", "/opt/x/run.sh", "/usr/bin/id"}); len(got) != 2 {
		t.Errorf("writer + executor of the same path: %v", got)
	}
	if got := RootEquivalentCommands([]string{"/usr/bin/cp /a /opt/bin/", "/opt/bin/tool"}); len(got) != 2 {
		t.Errorf("writer of a directory + executor below it: %v", got)
	}
}

func TestValidateProfile(t *testing.T) {
	ok := NormalizeProfile(Profile{Name: " nginx ", Class: ClassRestricted, Lecture: LectureOnce, TimestampTimeoutMin: 5,
		Commands: []string{" /usr/bin/systemctl restart nginx.service", "/usr/bin/systemctl restart nginx.service"}})
	if err := ValidateProfile(ok); err != nil || ok.Name != "nginx" || len(ok.Commands) != 1 {
		t.Fatalf("%+v %v", ok, err)
	}
	cases := map[string]struct {
		p    Profile
		want error
	}{
		"empty name":            {Profile{Class: ClassNone, Lecture: LectureOnce}, ErrInvalidName},
		"unknown class":         {Profile{Name: "x", Class: "admin", Lecture: LectureOnce}, ErrInvalidClass},
		"restricted no command": {Profile{Name: "x", Class: ClassRestricted, Lecture: LectureOnce}, ErrCommandsByClass},
		"full with command":     {Profile{Name: "x", Class: ClassFull, Lecture: LectureOnce, Commands: []string{"/usr/bin/id"}}, ErrCommandsByClass},
		"command with ALL":      {Profile{Name: "x", Class: ClassRestricted, Lecture: LectureOnce, Commands: []string{"ALL"}}, ErrInvalidCommand},
		"command with comma":    {Profile{Name: "x", Class: ClassRestricted, Lecture: LectureOnce, Commands: []string{"/usr/bin/a, /usr/bin/b"}}, ErrInvalidCommand},
		"negated command":       {Profile{Name: "x", Class: ClassRestricted, Lecture: LectureOnce, Commands: []string{"!/usr/bin/su"}}, ErrInvalidCommand},
		"timeout 61":            {Profile{Name: "x", Class: ClassNone, Lecture: LectureOnce, TimestampTimeoutMin: 61}, ErrInvalidScalars},
		"no lecture":            {Profile{Name: "x", Class: ClassNone}, ErrInvalidScalars},
	}
	for name, c := range cases {
		if err := ValidateProfile(NormalizeProfile(c.p)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if ValidateAssignmentSubject(SubjectGlobal, dave) == nil || ValidateAssignmentSubject(SubjectUser, uuid.Nil) == nil ||
		ValidateAssignmentSubject("device", dave) == nil || ValidateAssignmentSubject(SubjectGroup, ops) != nil {
		t.Error("ValidateAssignmentSubject")
	}
}

// Generators of the property tests: a small universe of IDs so that assignments, groups and scopes overlap.

var (
	userIDs  = []uuid.UUID{dave, uuid.MustParse("00000000-0000-4000-8000-0000000000d2")}
	groupIDs = []uuid.UUID{ops, web, uuid.MustParse("00000000-0000-4000-8000-0000000000a3")}
	dgIDs    = []uuid.UUID{servers, laptops}
	cmdPool  = []string{
		"/usr/bin/systemctl restart nginx.service", "/usr/bin/journalctl -u nginx.service", "/usr/bin/id",
		"/usr/bin/tee /opt/x/run.sh", "/opt/x/run.sh", "/usr/bin/apt-get update", "/usr/local/bin/backup",
	}
)

func genProfile(t *rapid.T, i int) Profile {
	class := rapid.SampledFrom([]Class{ClassNone, ClassRestricted, ClassFull}).Draw(t, "class")
	p := Profile{
		ID: uuid.UUID{0x20, 15: byte(i)}, Name: "p", Class: class,
		RequirePassword:     rapid.Bool().Draw(t, "require_password"),
		TimestampTimeoutMin: rapid.IntRange(0, 60).Draw(t, "timeout"),
		Lecture:             rapid.SampledFrom([]Lecture{LectureAlways, LectureOnce, LectureNever}).Draw(t, "lecture"),
	}
	if class == ClassRestricted {
		p.Commands = rapid.SliceOfNDistinct(rapid.SampledFrom(cmdPool), 1, 4, rapid.ID[string]).Draw(t, "commands")
	}
	return p
}

func genInput(t *rapid.T) Input {
	n := rapid.IntRange(0, 5).Draw(t, "profiles")
	in := Input{
		UserID:       rapid.SampledFrom(userIDs).Draw(t, "user"),
		UserGroups:   rapid.SliceOfNDistinct(rapid.SampledFrom(groupIDs), 0, 3, rapid.ID[uuid.UUID]).Draw(t, "user_groups"),
		DeviceGroups: rapid.SliceOfNDistinct(rapid.SampledFrom(dgIDs), 0, 2, rapid.ID[uuid.UUID]).Draw(t, "device_groups"),
	}
	for i := range n {
		in.Profiles = append(in.Profiles, genProfile(t, i))
	}
	if n == 0 {
		return in
	}
	for i := range rapid.IntRange(0, 8).Draw(t, "assignments") {
		a := Assignment{
			ID:          uuid.UUID{0x30, 15: byte(i)},
			ProfileID:   in.Profiles[rapid.IntRange(0, n-1).Draw(t, "profile")].ID,
			SubjectType: rapid.SampledFrom([]SubjectType{SubjectGlobal, SubjectGroup, SubjectUser}).Draw(t, "subject_type"),
		}
		switch a.SubjectType {
		case SubjectGroup:
			a.SubjectID = rapid.SampledFrom(groupIDs).Draw(t, "group")
		case SubjectUser:
			a.SubjectID = rapid.SampledFrom(userIDs).Draw(t, "subject_user")
		}
		if rapid.Bool().Draw(t, "scoped") {
			a.DeviceGroupID = rapid.SampledFrom(dgIDs).Draw(t, "scope")
		}
		in.Assignments = append(in.Assignments, a)
	}
	return in
}

func permuted[T any](t *rapid.T, label string, s []T) []T {
	out := slices.Clone(s)
	for i := len(out) - 1; i > 0; i-- {
		j := rapid.IntRange(0, i).Draw(t, label)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func reversed[T any](s []T) []T {
	out := slices.Clone(s)
	slices.Reverse(out)
	return out
}

func encode(t interface{ Fatal(...any) }, e EffectiveProfile) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPropertyPermutationInvariance (gate P1): permuting every input list gives a byte-identical effective profile.
func TestPropertyPermutationInvariance(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := genInput(t)
		perm := Input{
			UserID: in.UserID, UserGroups: permuted(t, "ug", in.UserGroups), DeviceGroups: permuted(t, "dg", in.DeviceGroups),
			Assignments: permuted(t, "a", in.Assignments), Profiles: permuted(t, "p", in.Profiles),
		}
		if a, b := encode(t, Effective(in)), encode(t, Effective(perm)); !bytes.Equal(a, b) {
			t.Fatalf("permutation changed the output:\n%s\n%s", a, b)
		}
	})
}

// TestPropertyMaxAndUnion: the class is the maximum of the applicable profiles' classes, the commands are exactly the
// union of their commands, and every command and the class are derived from an applicable assignment.
func TestPropertyMaxAndUnion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := genInput(t)
		e := Effective(in)
		byID := map[uuid.UUID]Profile{}
		for _, p := range in.Profiles {
			byID[p.ID] = p
		}
		class, union := ClassNone, []string{}
		applicable := map[uuid.UUID]bool{}
		for _, a := range in.Assignments {
			if applies(a, in) {
				applicable[a.ID] = true
				class = MaxReportedClass(class, byID[a.ProfileID].Class)
				union = append(union, byID[a.ProfileID].Commands...)
			}
		}
		slices.Sort(union)
		union = slices.Compact(union)
		if e.Class != class || !slices.Equal(e.Commands, union) {
			t.Fatalf("class %s commands %v; want %s %v", e.Class, e.Commands, class, union)
		}
		for _, d := range e.Derivation {
			if !applicable[d.AssignmentID] {
				t.Fatalf("derivation from a non-applicable assignment: %+v", d)
			}
		}
		for _, c := range e.Commands {
			if !slices.ContainsFunc(e.Derivation, func(d Derivation) bool { return d.Kind == DerivedCommand && d.Item == c }) {
				t.Fatalf("command %s has no derivation", c)
			}
		}
		if e.ReportedClass.rank() < e.Class.rank() || (e.ReportedClass != e.Class) != (e.Class == ClassRestricted && e.RootEquivalent) {
			t.Fatalf("reported class %s for class %s, root equivalent %v", e.ReportedClass, e.Class, e.RootEquivalent)
		}
	})
}

// TestPropertyMonotonic: an additional assignment never lowers the class and never removes a command.
func TestPropertyMonotonic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := genInput(t)
		if len(in.Profiles) == 0 {
			return
		}
		before := Effective(in)
		extra := Assignment{
			ID: uuid.UUID{0x40}, ProfileID: rapid.SampledFrom(in.Profiles).Draw(t, "extra").ID, SubjectType: SubjectGlobal,
		}
		after := Effective(Input{UserID: in.UserID, UserGroups: in.UserGroups, DeviceGroups: in.DeviceGroups,
			Assignments: append(slices.Clone(in.Assignments), extra), Profiles: in.Profiles})
		if after.Class.rank() < before.Class.rank() {
			t.Fatalf("class dropped from %s to %s", before.Class, after.Class)
		}
		for _, c := range before.Commands {
			if !slices.Contains(after.Commands, c) {
				t.Fatalf("command %s lost", c)
			}
		}
	})
}

// TestPropertyScopeOutsideDevice: assignments scoped to device groups the device is not in have no effect.
func TestPropertyScopeOutsideDevice(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := genInput(t)
		var kept []Assignment
		for _, a := range in.Assignments {
			if a.DeviceGroupID == uuid.Nil || slices.Contains(in.DeviceGroups, a.DeviceGroupID) {
				kept = append(kept, a)
			}
		}
		reduced := in
		reduced.Assignments = kept
		if a, b := encode(t, Effective(in)), encode(t, Effective(reduced)); !bytes.Equal(a, b) {
			t.Fatalf("out-of-scope assignments changed the output:\n%s\n%s", a, b)
		}
	})
}

// TestGoldenSudoersPermutation (gate P1): the sudoers file rendered from permuted inputs is byte-identical.
func TestGoldenSudoersPermutation(t *testing.T) {
	assignments := []Assignment{
		assign(1, pBase, SubjectGlobal, uuid.Nil, uuid.Nil), assign(2, pNginx, SubjectGroup, ops, uuid.Nil),
		assign(3, pLogs, SubjectGroup, web, laptops),
	}
	render := func(in Input) []byte {
		entry, ok, err := Effective(in).SudoEntry("dave@acme.test")
		if err != nil || !ok {
			t.Fatalf("%v %v", ok, err)
		}
		out, err := sudoers.Render(entry, sudoers.PlaceholderUID, sudoers.Classic)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := render(Input{UserID: dave, UserGroups: []uuid.UUID{ops, web}, DeviceGroups: []uuid.UUID{laptops, servers},
		Assignments: assignments, Profiles: profiles})
	got := render(Input{UserID: dave, UserGroups: []uuid.UUID{web, ops}, DeviceGroups: []uuid.UUID{servers, laptops},
		Assignments: []Assignment{assignments[2], assignments[0], assignments[1]}, Profiles: reversed(profiles)})
	if !bytes.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	golden := "# Managed by Paddock. Do not edit. User dave@acme.test, profile digest "
	if !bytes.HasPrefix(want, []byte(golden)) || !bytes.Contains(want, []byte(
		"#4294967294 ALL=(root) /usr/bin/journalctl -u nginx.service, /usr/bin/systemctl restart nginx.service\n")) ||
		!bytes.Contains(want, []byte("Defaults:#4294967294 lecture=once, lecture_file=/etc/paddock/sudo_lecture, timestamp_timeout=5\n")) {
		t.Fatalf("rendered\n%s", want)
	}
}
