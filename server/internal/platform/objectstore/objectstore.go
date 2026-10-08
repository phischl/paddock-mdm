// Package objectstore is the S3 client for the object store (RustFS by default, ADR 0017). Only the S3 API and
// Object Lock are used, never vendor-specific APIs.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Store is a bucket.
type Store struct {
	client *s3.Client
	bucket string
}

// New creates a path-style client for endpoint and bucket.
func New(endpoint, accessKey, secretKey, bucket string) *Store {
	return &Store{
		client: s3.New(s3.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(endpoint),
			UsePathStyle: true,
			Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		}),
		bucket: bucket,
	}
}

// Bucket returns the bucket name.
func (s *Store) Bucket() string { return s.bucket }

// Ping checks that the bucket is reachable with the credential.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	return err
}

// PutLocked writes an object with COMPLIANCE retention until retainUntil.
func (s *Store) PutLocked(ctx context.Context, key, contentType string, body []byte, retainUntil time.Time) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    &s.bucket,
		Key:                       &key,
		Body:                      bytes.NewReader(body),
		ContentType:               &contentType,
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(retainUntil.UTC()),
	})
	return err
}

// ErrNotFound means the object does not exist.
var ErrNotFound = errors.New("objectstore: not found")

// Get reads the current version of an object.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()
	return io.ReadAll(out.Body)
}

// Retention returns the retention mode and date of the current version.
func (s *Store) Retention(ctx context.Context, key string) (types.ObjectLockRetentionMode, time.Time, error) {
	out, err := s.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return "", time.Time{}, err
	}
	if out.Retention == nil || out.Retention.RetainUntilDate == nil {
		return "", time.Time{}, errors.New("objectstore: no retention")
	}
	return out.Retention.Mode, *out.Retention.RetainUntilDate, nil
}

// DefaultRetention returns the bucket's Object Lock state and default retention ("" and 0 without a default rule).
func (s *Store) DefaultRetention(ctx context.Context) (enabled bool, mode types.ObjectLockRetentionMode, days int32, err error) {
	out, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &s.bucket})
	if err != nil {
		return false, "", 0, err
	}
	c := out.ObjectLockConfiguration
	if c == nil {
		return false, "", 0, nil
	}
	enabled = c.ObjectLockEnabled == types.ObjectLockEnabledEnabled
	if c.Rule != nil && c.Rule.DefaultRetention != nil {
		mode = types.ObjectLockRetentionMode(c.Rule.DefaultRetention.Mode)
		days = aws.ToInt32(c.Rule.DefaultRetention.Days)
	}
	return enabled, mode, days, nil
}

// Newest returns the last-modified time of the newest object below prefix; found is false when there is none. It
// needs s3:ListBucket only.
func (s *Store) Newest(ctx context.Context, prefix string) (newest time.Time, found bool, err error) {
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return time.Time{}, false, err
		}
		for _, o := range page.Contents {
			if t := aws.ToTime(o.LastModified); !found || t.After(newest) {
				newest, found = t, true
			}
		}
	}
	return newest, found, nil
}

// List returns the keys below prefix.
func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
	}
	return keys, nil
}

// DeleteAllVersions deletes every version and delete marker of every object below prefix in a versioned bucket and
// returns how many it deleted. Nothing below prefix is recoverable afterwards (crypto-shredding of a Destroy, plan
// M4c decision 9).
func (s *Store) DeleteAllVersions(ctx context.Context, prefix string) (int, error) {
	n := 0
	for {
		page, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &s.bucket, Prefix: &prefix})
		if err != nil {
			return n, err
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
				return n, err
			}
			n++
		}
		// The deleted versions are gone from the next listing, which therefore starts at the beginning again.
		if !aws.ToBool(page.IsTruncated) {
			return n, nil
		}
	}
}

// GetIfExists reads the current version of an object; found is false if it does not exist.
func (s *Store) GetIfExists(ctx context.Context, key string) (data []byte, found bool, err error) {
	data, err = s.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	return data, err == nil, err
}

// Presigner computes presigned GET and PUT URLs locally (no network call) for a public endpoint, e.g.
// https://bundles.<domain>, through which the object store is reachable (architecture §7.3).
type Presigner struct {
	client *s3.PresignClient
	bucket string
}

// NewPresigner creates a presigner for the public endpoint; the credential only needs read access.
func NewPresigner(publicEndpoint, accessKey, secretKey, bucket string) *Presigner {
	return &Presigner{client: s3.NewPresignClient(New(publicEndpoint, accessKey, secretKey, bucket).client), bucket: bucket}
}

// PresignGet returns a GET URL for key that is valid for ttl.
func (p *Presigner) PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	req, err := p.client.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &p.bucket, Key: &key}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// PresignPut returns a PUT URL for key that is valid for ttl (escrowed LUKS headers, plan M4b decision 10). The
// signature covers the bucket and the key, so the URL cannot write anywhere else.
func (p *Presigner) PresignPut(ctx context.Context, key string, ttl time.Duration) (string, error) {
	req, err := p.client.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &p.bucket, Key: &key}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// Put writes an object without retention (bundles bucket).
func (s *Store) Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(body), ContentType: &contentType, CacheControl: &cacheControl,
	})
	return err
}
