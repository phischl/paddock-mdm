package objectstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Options configure a store on an endpoint the platform administrator names (a backup target, plan M15 §6.1).
type Options struct {
	// Region signs the requests; empty means us-east-1.
	Region string
	// CAPEM, when set, is the only trust anchor for the endpoint's certificate.
	CAPEM string
}

// NewWithOptions creates a path-style client for endpoint and bucket with o's region and trust anchor.
func NewWithOptions(endpoint, accessKey, secretKey, bucket string, o Options) (*Store, error) {
	region := o.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	}
	if o.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(o.CAPEM)) {
			return nil, errors.New("objectstore: the CA holds no PEM certificate")
		}
		opts.HTTPClient = awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
			t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		})
	}
	return &Store{client: s3.New(opts), bucket: bucket}, nil
}

// ListSizes returns the size of every object below prefix, keyed by the object key.
func (s *Store) ListSizes(ctx context.Context, prefix string) (map[string]int64, error) {
	return s.ListSizesPaged(ctx, prefix, func() {})
}

// ListSizesPaged is ListSizes and calls page after every page of the listing.
func (s *Store) ListSizesPaged(ctx context.Context, prefix string, page func()) (map[string]int64, error) {
	out := map[string]int64{}
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for p.HasMorePages() {
		res, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, o := range res.Contents {
			out[aws.ToString(o.Key)] = aws.ToInt64(o.Size)
		}
		page()
	}
	return out, nil
}

// ObjectInfo is the size and the modification time (S3 LastModified) of one listed object.
type ObjectInfo struct {
	Size     int64
	Modified time.Time
}

// ListInfo returns the size and LastModified of every object below prefix, keyed by the object key. On a versioned
// bucket LastModified is the time of the current version.
func (s *Store) ListInfo(ctx context.Context, prefix string) (map[string]ObjectInfo, error) {
	out := map[string]ObjectInfo{}
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			out[aws.ToString(o.Key)] = ObjectInfo{Size: aws.ToInt64(o.Size), Modified: aws.ToTime(o.LastModified)}
		}
	}
	return out, nil
}

// PutReader writes an object of size bytes from body without retention. body is seekable, so the request can be
// signed and retried without buffering the object in memory.
func (s *Store) PutReader(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	ct := "application/octet-stream"
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: body, ContentLength: aws.Int64(size), ContentType: &ct,
	})
	return err
}

// Delete removes the current version of an object; a missing object is no error.
func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	return err
}
