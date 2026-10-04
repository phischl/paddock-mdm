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

// Presigner computes presigned GET URLs locally (no network call) for a public endpoint, e.g.
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

// Put writes an object without retention (bundles bucket).
func (s *Store) Put(ctx context.Context, key, contentType, cacheControl string, body []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(body), ContentType: &contentType, CacheControl: &cacheControl,
	})
	return err
}
