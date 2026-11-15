package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ErrRetained marks a delete the object store refused because the version is under Object Lock retention or a legal
// hold. A purge that hits one does not report success: the organization deletion records it (plan M17 amendment k).
var ErrRetained = errors.New("objectstore: retained by object lock")

// Purge is the outcome of PurgeObjects or PurgeVersions: how many objects or versions were deleted, and the keys whose
// deletion Object Lock refused.
type Purge struct {
	Deleted  int
	Retained []string
}

// retainedError reports whether err is the object store's refusal to delete a version under retention or legal hold.
// S3 answers 403 AccessDenied with an Object Lock message (AWS: "Access Denied because object protected by object
// lock"), some implementations an error code of their own; a plain AccessDenied of a missing grant is not one.
func retainedError(err error) bool {
	// smithy.APIError's methods, so the module needs no direct dependency on smithy-go.
	var api interface {
		ErrorCode() string
		ErrorMessage() string
	}
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "ObjectLocked", "ObjectLockedByRetention", "ObjectLockedByLegalHold", "ObjectUnderLegalHold", "ObjectRetained":
		return true
	}
	msg := strings.ToLower(api.ErrorMessage())
	if !strings.Contains(msg, "object lock") && !strings.Contains(msg, "retention") && !strings.Contains(msg, "legal hold") &&
		!strings.Contains(msg, "locked") && !strings.Contains(msg, "worm") {
		return false
	}
	var resp *awshttp.ResponseError
	return !errors.As(err, &resp) || resp.HTTPStatusCode() == http.StatusForbidden || resp.HTTPStatusCode() == http.StatusBadRequest
}

// result returns p and, when a deletion was refused by Object Lock, an error wrapping ErrRetained.
func (p Purge) result(prefix string) (Purge, error) {
	if len(p.Retained) > 0 {
		return p, fmt.Errorf("%w: %d of the objects below %s", ErrRetained, len(p.Retained), prefix)
	}
	return p, nil
}

// PurgeObjects deletes every object below prefix in an unversioned bucket with s3:ListBucket and s3:DeleteObject only.
// A deletion Object Lock refuses is recorded and the purge goes on; any other error stops it.
func (s *Store) PurgeObjects(ctx context.Context, prefix string) (Purge, error) {
	var out Purge
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, o := range page.Contents {
			if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: o.Key}); err != nil {
				if !retainedError(err) {
					return out, err
				}
				out.Retained = append(out.Retained, aws.ToString(o.Key))
				continue
			}
			out.Deleted++
		}
	}
	return out.result(prefix)
}

// PurgeVersions deletes every version and delete marker below prefix in a versioned bucket with s3:ListBucketVersions
// and s3:DeleteObjectVersion only. Unlike DeleteAllVersions it pages with the listing's markers, so a version Object
// Lock keeps is listed once and recorded rather than listed again forever, and the purge goes on past it.
func (s *Store) PurgeVersions(ctx context.Context, prefix string) (Purge, error) {
	var out Purge
	in := &s3.ListObjectVersionsInput{Bucket: &s.bucket, Prefix: &prefix}
	for {
		page, err := s.client.ListObjectVersions(ctx, in)
		if err != nil {
			return out, err
		}
		type version struct{ key, id *string }
		var all []version
		for _, v := range page.Versions {
			all = append(all, version{v.Key, v.VersionId})
		}
		for _, m := range page.DeleteMarkers {
			all = append(all, version{m.Key, m.VersionId})
		}
		for _, v := range all {
			if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: v.key, VersionId: v.id}); err != nil {
				if !retainedError(err) {
					return out, err
				}
				out.Retained = append(out.Retained, aws.ToString(v.key))
				continue
			}
			out.Deleted++
		}
		if !aws.ToBool(page.IsTruncated) {
			return out.result(prefix)
		}
		in.KeyMarker, in.VersionIdMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}
