// Package s3test starts the pinned RustFS with an Object Lock bucket like rustfs-audit-bootstrap.sh does, or with a
// plain bucket like rustfs-bundles-bootstrap.sh does.
package s3test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// Root credentials of the throwaway test RustFS.
const (
	RootUser     = "rustfs-test-root"
	RootPassword = "rustfs-test-root-password"
)

// RustFS is a running object store with one bucket.
type RustFS struct {
	Endpoint string
	Bucket   string
	Root     *s3.Client
}

// Start starts RustFS and creates bucket with Object Lock and default retention COMPLIANCE / 400 days.
func Start(t testing.TB, bucket string) *RustFS {
	t.Helper()
	ctx := context.Background()
	r := start(t, bucket)
	if err := createBucket(ctx, r.Root, &s3.CreateBucketInput{Bucket: &bucket, ObjectLockEnabledForBucket: aws.Bool(true)}, bucketReadyTimeout); err != nil {
		t.Fatalf("s3test: create bucket: %v", err)
	}
	_, err := r.Root.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket: &bucket,
		ObjectLockConfiguration: &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{DefaultRetention: &types.DefaultRetention{
				Mode: types.ObjectLockRetentionModeCompliance, Days: aws.Int32(400),
			}},
		},
	})
	if err != nil {
		t.Fatalf("s3test: object lock configuration: %v", err)
	}
	return r
}

// StartPlain starts RustFS and creates bucket without versioning and Object Lock.
func StartPlain(t testing.TB, bucket string) *RustFS {
	t.Helper()
	r := start(t, bucket)
	if err := createBucket(context.Background(), r.Root, &s3.CreateBucketInput{Bucket: &bucket}, bucketReadyTimeout); err != nil {
		t.Fatalf("s3test: create bucket: %v", err)
	}
	return r
}

// StartVersioned starts RustFS and creates bucket with versioning and without Object Lock, like paddock-escrow.
func StartVersioned(t testing.TB, bucket string) *RustFS {
	t.Helper()
	ctx := context.Background()
	r := StartPlain(t, bucket)
	_, err := r.Root.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
	})
	if err != nil {
		t.Fatalf("s3test: versioning: %v", err)
	}
	return r
}

// bucketReadyTimeout bounds how long createBucket retries. RustFS answers /health before it accepts S3 requests and,
// on a loaded machine, answers 503 for longer than the SDK's three attempts (PDK-011).
const bucketReadyTimeout = time.Minute

// createBucket creates the bucket, retrying while RustFS answers 503 Service Unavailable, at most for timeout. A bucket
// that an attempt answered with 503 may still have created counts as created.
func createBucket(ctx context.Context, client *s3.Client, in *s3.CreateBucketInput, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	backoff := 100 * time.Millisecond
	retried := false
	for {
		_, err := client.CreateBucket(ctx, in)
		var owned *types.BucketAlreadyOwnedByYou
		if err == nil || (retried && errors.As(err, &owned)) {
			return nil
		}
		var resp *awshttp.ResponseError
		if !errors.As(err, &resp) || resp.HTTPStatusCode() != http.StatusServiceUnavailable || time.Now().Add(backoff).After(deadline) {
			return err
		}
		retried = true
		time.Sleep(backoff)
		backoff = min(2*backoff, 2*time.Second)
	}
}

func start(t testing.TB, bucket string) *RustFS {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        pgtest.Image(t, "RUSTFS_IMAGE"),
			ExposedPorts: []string{"9000/tcp"},
			Env: map[string]string{
				"RUSTFS_ACCESS_KEY": RootUser, "RUSTFS_SECRET_KEY": RootPassword,
				"RUSTFS_CONSOLE_ENABLE": "false", "RUSTFS_OBS_LOG_DIRECTORY": "",
			},
			WaitingFor: wait.ForHTTP("/health").WithPort("9000/tcp").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("s3test: start rustfs: %v", err)
	}
	host, _ := c.Host(ctx)
	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	r := &RustFS{Endpoint: fmt.Sprintf("http://%s:%s", host, port.Port()), Bucket: bucket}
	r.Root = s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(r.Endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(RootUser, RootPassword, ""),
	})
	return r
}
