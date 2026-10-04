package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/policy"
)

// File reconciles file resources: content, mode, owner and group.
type File struct {
	Sys     System
	Managed *Managed
}

// Type implements Reconciler.
func (f *File) Type() string { return bundle.TypeFile }

// fileSpec is a validated file resource.
type fileSpec struct {
	bundle.FileSpec
	mode     fs.FileMode
	uid, gid int
}

func (f *File) spec(r bundle.Resource) (fileSpec, error) {
	var s fileSpec
	if err := json.Unmarshal(r.Spec, &s.FileSpec); err != nil {
		return s, fmt.Errorf("invalid file spec: %w", err)
	}
	// Defence in depth: the server enforces the same policy before it signs a bundle.
	if err := errors.Join(policy.ValidatePath(s.Path), policy.ValidateMode(s.Mode), policy.ValidateOwner(s.Owner),
		policy.ValidateOwner(s.Group)); err != nil {
		return s, err
	}
	if sum := sha256.Sum256([]byte(s.Content)); hex.EncodeToString(sum[:]) != s.ContentSHA256 {
		return s, errors.New("content does not match content_sha256")
	}
	mode, _ := strconv.ParseUint(s.Mode, 8, 32) // validated above
	s.mode = fs.FileMode(mode)
	var err error
	if s.uid, err = f.Sys.LookupUser(s.Owner); err != nil {
		return s, fmt.Errorf("owner %s: %w", s.Owner, err)
	}
	if s.gid, err = f.Sys.LookupGroup(s.Group); err != nil {
		return s, fmt.Errorf("group %s: %w", s.Group, err)
	}
	return s, nil
}

// Plan implements Reconciler.
func (f *File) Plan(_ context.Context, r bundle.Resource) ([]string, error) {
	s, err := f.spec(r)
	if err != nil {
		return nil, err
	}
	return f.plan(s)
}

func (f *File) plan(s fileSpec) ([]string, error) {
	data, info, err := f.Sys.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{"create"}, nil
	}
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []string{"replace " + info.Mode().Type().String()}, nil
	}
	var changes []string
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != s.ContentSHA256 {
		changes = append(changes, "content")
	}
	if info.Mode().Perm() != s.mode || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		changes = append(changes, fmt.Sprintf("mode %04o → %04o", info.Mode().Perm(), s.mode))
	}
	uid, gid := f.Sys.Owner(info)
	if uid != s.uid {
		changes = append(changes, fmt.Sprintf("owner %d → %s", uid, s.Owner))
	}
	if gid != s.gid {
		changes = append(changes, fmt.Sprintf("group %d → %s", gid, s.Group))
	}
	return changes, nil
}

// Apply implements Reconciler. The file is always rewritten as a whole, so content, mode and owner change in one
// atomic rename.
func (f *File) Apply(ctx context.Context, r bundle.Resource) Result {
	s, err := f.spec(r)
	if err != nil {
		return errorResult(r.ID, err)
	}
	return apply(ctx, r, func(context.Context, bundle.Resource) ([]string, error) { return f.plan(s) }, func([]string) error {
		if err := f.Sys.WriteFileAtomic(s.Path, []byte(s.Content), s.mode, s.uid, s.gid); err != nil {
			return err
		}
		return f.Managed.Record(s.Path, s.ContentSHA256)
	})
}

// Remove deletes a file that left the bundle if Paddock wrote it and nobody changed it since. It returns
// ErrModified (and keeps the file) if the content differs from what Paddock wrote. Either way the file is no longer
// managed afterwards.
func (f *File) Remove(path string) error {
	sum, ok := f.Managed.Files[path]
	if !ok {
		return nil
	}
	data, _, err := f.Sys.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		cur := sha256.Sum256(data)
		if data == nil || hex.EncodeToString(cur[:]) != sum {
			if err := f.Managed.Forget(path); err != nil {
				return err
			}
			return ErrModified
		}
		if err := f.Sys.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return f.Managed.Forget(path)
}

// ErrModified is the message of a removed file resource whose file was changed locally (plan M2b decision 10).
var ErrModified = errors.New("left_modified_file")
