package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ErrRetained marks a delete the object store refused because the version is under Object Lock retention or a legal
// hold. A purge that hits one does not report success: the organization deletion records it (plan M17 amendment k).
var ErrRetained = errors.New("objectstore: retained by object lock")

// PurgeBatch is the most entries one listing page of a purge holds, and with it one DeleteObjects request (the S3
// limit; plan M17 amendment 2026-11-16 s point 1.4).
const PurgeBatch = 1000

// PurgeRequestTimeout bounds every S3 request of a purge, so one hanging request cannot hold the deletion round.
const PurgeRequestTimeout = 30 * time.Second

// Purge is the outcome of one PurgeObjects or PurgeVersions call: how many objects or versions it deleted, the keys
// whose deletion Object Lock refused, and whether the listing reached its end in this call.
type Purge struct {
	Deleted  int
	Retained []string
	Done     bool
}

// retainedKeyError reports whether a delete's error code and message are the object store's refusal to delete a
// version under retention or legal hold. S3 answers AccessDenied with an Object Lock message (AWS: "Access Denied
// because object protected by object lock"), some implementations an error code of their own; a plain AccessDenied of
// a missing grant is not one.
func retainedKeyError(code, message string) bool {
	if retainedCode(code) {
		return true
	}
	msg := strings.ToLower(message)
	return strings.Contains(msg, "object lock") || strings.Contains(msg, "retention") || strings.Contains(msg, "legal hold") ||
		strings.Contains(msg, "locked") || strings.Contains(msg, "worm")
}

// retainedCode reports whether code is an implementation's own error code for a delete Object Lock refused.
func retainedCode(code string) bool {
	switch code {
	case "ObjectLocked", "ObjectLockedByRetention", "ObjectLockedByLegalHold", "ObjectUnderLegalHold", "ObjectRetained":
		return true
	}
	return false
}

// result returns p and, when the listing ended and a deletion was refused by Object Lock, an error wrapping
// ErrRetained.
func (p Purge) result(prefix string) (Purge, error) {
	if p.Done && len(p.Retained) > 0 {
		return p, fmt.Errorf("%w: %d of the objects below %s", ErrRetained, len(p.Retained), prefix)
	}
	return p, nil
}

// yields reports whether the purge stops after the page it just finished: only once until has passed and the call
// has deleted something, so a call that meets only retained entries lists to the end and the step terminates.
func (p Purge) yields(until time.Time) bool {
	return !until.IsZero() && p.Deleted > 0 && !time.Now().Before(until)
}

// PurgeObjects deletes the objects below prefix in an unversioned bucket with s3:ListBucket and s3:DeleteObject only,
// one DeleteObjects request per listing page of at most PurgeBatch keys. It lists from the start of prefix: what an
// earlier call deleted is gone from the listing, so no position is kept. A deletion Object Lock refuses is recorded and
// the purge goes on; any other error stops it. A zero until means no bound; otherwise the call returns with Done false
// after the first page past until on which it deleted something.
func (s *Store) PurgeObjects(ctx context.Context, prefix string, until time.Time) (Purge, error) {
	var out Purge
	in := &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix, MaxKeys: aws.Int32(PurgeBatch)}
	for {
		lctx, cancel := context.WithTimeout(ctx, PurgeRequestTimeout)
		page, err := s.client.ListObjectsV2(lctx, in)
		cancel()
		if err != nil {
			return out, err
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, o := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: o.Key})
		}
		if err := s.deleteBatch(ctx, ids, &out); err != nil {
			return out, err
		}
		if !aws.ToBool(page.IsTruncated) {
			out.Done = true
			return out.result(prefix)
		}
		if out.yields(until) {
			return out, nil
		}
		in.ContinuationToken = page.NextContinuationToken
	}
}

// PurgeVersions deletes the versions and delete markers below prefix in a versioned bucket with s3:ListBucketVersions
// and s3:DeleteObjectVersion only, like PurgeObjects one DeleteObjects request per page. It pages with the listing's
// markers within a call, so a version Object Lock keeps is listed once per call and recorded rather than listed again
// forever, and the purge goes on past it.
func (s *Store) PurgeVersions(ctx context.Context, prefix string, until time.Time) (Purge, error) {
	var out Purge
	in := &s3.ListObjectVersionsInput{Bucket: &s.bucket, Prefix: &prefix, MaxKeys: aws.Int32(PurgeBatch)}
	for {
		lctx, cancel := context.WithTimeout(ctx, PurgeRequestTimeout)
		page, err := s.client.ListObjectVersions(lctx, in)
		cancel()
		if err != nil {
			return out, err
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Versions)+len(page.DeleteMarkers))
		for _, v := range page.Versions {
			ids = append(ids, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
		}
		for _, m := range page.DeleteMarkers {
			ids = append(ids, types.ObjectIdentifier{Key: m.Key, VersionId: m.VersionId})
		}
		if err := s.deleteBatch(ctx, ids, &out); err != nil {
			return out, err
		}
		if !aws.ToBool(page.IsTruncated) {
			out.Done = true
			return out.result(prefix)
		}
		if out.yields(until) {
			return out, nil
		}
		in.KeyMarker, in.VersionIdMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}

// deleteBatch deletes ids in one quiet DeleteObjects request and adds the outcome to out: a key Object Lock keeps goes
// to Retained, any other per-key error ends the purge after the deletions of this request are counted.
func (s *Store) deleteBatch(ctx context.Context, ids []types.ObjectIdentifier, out *Purge) error {
	if len(ids) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, PurgeRequestTimeout)
	defer cancel()
	res, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &s.bucket,
		Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)}})
	if err != nil {
		return err
	}
	out.Deleted += len(ids) - len(res.Errors)
	var failed error
	for _, e := range res.Errors {
		code, msg := aws.ToString(e.Code), aws.ToString(e.Message)
		retained := retainedKeyError(code, msg)
		if !retained && code == "AccessDenied" {
			// RustFS 1.0.4 reports a version under Object Lock in DeleteObjects as a plain "AccessDenied: Access Denied.",
			// the same as a missing grant; only the single delete's answer tells them apart (PDK-1087).
			var deleted bool
			if deleted, retained, err = s.deleteOne(ctx, e.Key, e.VersionId); err != nil {
				return err
			}
			if deleted {
				out.Deleted++
				continue
			}
		}
		if retained {
			out.Retained = append(out.Retained, aws.ToString(e.Key))
			continue
		}
		if failed == nil {
			failed = fmt.Errorf("objectstore: delete %s: %s: %s", aws.ToString(e.Key), code, msg)
		}
	}
	return failed
}

// deleteOne deletes one key or version whose deletion DeleteObjects refused with AccessDenied, and reports whether it
// is gone now or retained by Object Lock; any other refusal is retained false without an error, and the caller reports
// the original one.
func (s *Store) deleteOne(ctx context.Context, key, version *string) (deleted, retained bool, err error) {
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: key, VersionId: version})
	switch {
	case err == nil:
		return true, false, nil
	case retainedError(err):
		return false, true, nil
	}
	var api interface{ ErrorCode() string }
	if errors.As(err, &api) && api.ErrorCode() == "AccessDenied" {
		return false, false, nil
	}
	return false, false, err
}

// retainedError reports whether err of a single delete is the object store's refusal to delete a version under
// retention or legal hold: a lock code, or a lock message with status 403 or 400.
func retainedError(err error) bool {
	// smithy.APIError's methods, so the module needs no direct dependency on smithy-go.
	var api interface {
		ErrorCode() string
		ErrorMessage() string
	}
	if !errors.As(err, &api) || !retainedKeyError(api.ErrorCode(), api.ErrorMessage()) {
		return false
	}
	if retainedCode(api.ErrorCode()) {
		return true
	}
	var resp *awshttp.ResponseError
	return !errors.As(err, &resp) || resp.HTTPStatusCode() == http.StatusForbidden || resp.HTTPStatusCode() == http.StatusBadRequest
}
