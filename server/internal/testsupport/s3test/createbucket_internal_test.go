package s3test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeS3 answers CreateBucket with status for the first unavailable requests, then with ok.
func fakeS3(t *testing.T, unavailable int32, status, ok int, okBody string) (*s3.Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= unavailable {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>ServiceUnavailable</Code><Message>not ready</Message></Error>`))
			return
		}
		w.WriteHeader(ok)
		_, _ = w.Write([]byte(okBody))
	}))
	t.Cleanup(srv.Close)
	// One attempt per call, so that the test counts createBucket's own retries.
	client := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(srv.URL), UsePathStyle: true, RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
	})
	return client, &calls
}

// TestCreateBucketWaitsForRustFS is the regression of PDK-011: RustFS answered 503 to CreateBucket right after its
// health check passed; createBucket retries until the bucket is created.
func TestCreateBucketWaitsForRustFS(t *testing.T) {
	client, calls := fakeS3(t, 5, http.StatusServiceUnavailable, http.StatusOK, "")
	if err := createBucket(context.Background(), client, &s3.CreateBucketInput{Bucket: aws.String("b")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 6 {
		t.Fatalf("%d requests, want 6", n)
	}
}

// TestCreateBucketAlreadyCreatedByARetriedAttempt: an attempt answered with 503 may have created the bucket, so the
// next attempt's BucketAlreadyOwnedByYou counts as created.
func TestCreateBucketAlreadyCreatedByARetriedAttempt(t *testing.T) {
	owned := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>BucketAlreadyOwnedByYou</Code><Message>owned</Message></Error>`
	client, _ := fakeS3(t, 1, http.StatusServiceUnavailable, http.StatusConflict, owned)
	if err := createBucket(context.Background(), client, &s3.CreateBucketInput{Bucket: aws.String("b")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Without a retry, an existing bucket is an error (a test reusing a bucket name).
	client, _ = fakeS3(t, 0, http.StatusServiceUnavailable, http.StatusConflict, owned)
	if err := createBucket(context.Background(), client, &s3.CreateBucketInput{Bucket: aws.String("b")}, time.Minute); err == nil {
		t.Fatal("an existing bucket without a retried attempt must fail")
	}
}

// TestCreateBucketIsBounded: createBucket gives up after its timeout and does not retry other errors.
func TestCreateBucketIsBounded(t *testing.T) {
	client, _ := fakeS3(t, 1<<30, http.StatusServiceUnavailable, http.StatusOK, "")
	start := time.Now()
	if err := createBucket(context.Background(), client, &s3.CreateBucketInput{Bucket: aws.String("b")}, time.Second); err == nil {
		t.Fatal("a RustFS that stays unavailable must fail")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("gave up after %s, timeout 1s", d)
	}
	client, calls := fakeS3(t, 1<<30, http.StatusForbidden, http.StatusOK, "")
	if err := createBucket(context.Background(), client, &s3.CreateBucketInput{Bucket: aws.String("b")}, time.Minute); err == nil || calls.Load() != 1 {
		t.Fatalf("403: err %v after %d requests, want an error after 1", err, calls.Load())
	}
}
