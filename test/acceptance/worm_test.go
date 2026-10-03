package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// TestWORM is the audit gate A1 (plan M0 §8): an object in the WORM bucket cannot be deleted or have its
// retention shortened or weakened, not even with the root credentials of the object store.
func TestWORM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := s3Client(t, mustSecret(t, "rustfs_audit_root_user"), mustSecret(t, "rustfs_audit_root_password"))
	writer := s3Client(t, mustSecret(t, "rustfs_audit_writer_access_key"), mustSecret(t, "rustfs_audit_writer_secret_key"))
	bucket := stack.AuditBucket()

	lock, err := root.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: &bucket})
	if err != nil {
		t.Fatalf("get object lock configuration: %v", err)
	}
	if lock.ObjectLockConfiguration == nil || lock.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled ||
		lock.ObjectLockConfiguration.Rule == nil || lock.ObjectLockConfiguration.Rule.DefaultRetention == nil ||
		lock.ObjectLockConfiguration.Rule.DefaultRetention.Mode != types.ObjectLockRetentionModeCompliance {
		t.Fatalf("bucket %s has no COMPLIANCE default retention: %+v", bucket, lock.ObjectLockConfiguration)
	}

	body := make([]byte, 4096)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(body)
	key := "acceptance/worm/" + uuid.NewString() + ".bin"
	retainUntil := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	put, err := root.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       &key,
		Body:                      bytes.NewReader(body),
		ObjectLockMode:            types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: &retainUntil,
	})
	if err != nil {
		t.Fatalf("put object with COMPLIANCE retention (root): %v", err)
	}
	if put.VersionId == nil || *put.VersionId == "" {
		t.Fatal("put object returned no version ID; Object Lock requires versioning")
	}
	version := put.VersionId
	t.Logf("object %s version %s retained until %s", key, *version, retainUntil.Format(time.RFC3339))

	t.Run("root cannot delete the version", func(t *testing.T) {
		_, err := root.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
		expectError(t, "DeleteObject(versionId) as root", err)
	})

	t.Run("root cannot shorten retention", func(t *testing.T) {
		shorter := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		_, err := root.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket, Key: &key, VersionId: version,
			Retention: &types.ObjectLockRetention{Mode: types.ObjectLockRetentionModeCompliance, RetainUntilDate: &shorter},
		})
		expectError(t, "PutObjectRetention(shorter) as root", err)
	})

	t.Run("root cannot bypass governance retention", func(t *testing.T) {
		_, err := root.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket, Key: &key, VersionId: version, BypassGovernanceRetention: aws.Bool(true),
		})
		expectError(t, "DeleteObject(versionId, bypass governance) as root", err)
	})

	t.Run("root cannot switch to GOVERNANCE", func(t *testing.T) {
		_, err := root.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket, Key: &key, VersionId: version,
			Retention: &types.ObjectLockRetention{Mode: types.ObjectLockRetentionModeGovernance, RetainUntilDate: &retainUntil},
		})
		expectError(t, "PutObjectRetention(GOVERNANCE) as root", err)
	})

	t.Run("writer cannot delete the version", func(t *testing.T) {
		_, err := writer.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
		expectError(t, "DeleteObject(versionId) as writer", err)
	})

	t.Run("writer cannot change the bucket policy", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:DeleteObject"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}]}`
		_, err := writer.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy})
		expectError(t, "PutBucketPolicy as writer", err)
	})

	// Positive control: retention calls are not rejected wholesale; extending is allowed (architecture §14.4).
	t.Run("writer can extend retention", func(t *testing.T) {
		longer := retainUntil.Add(time.Hour)
		_, err := writer.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
			Bucket: &bucket, Key: &key, VersionId: version,
			Retention: &types.ObjectLockRetention{Mode: types.ObjectLockRetentionModeCompliance, RetainUntilDate: &longer},
		})
		if err != nil {
			t.Fatalf("extending retention as writer failed: %v", err)
		}
	})

	t.Run("object unchanged and still locked", func(t *testing.T) {
		got, err := root.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: version})
		if err != nil {
			t.Fatalf("get object: %v", err)
		}
		defer got.Body.Close()
		data, err := io.ReadAll(got.Body)
		if err != nil {
			t.Fatalf("read object: %v", err)
		}
		if sha256.Sum256(data) != wantSum {
			t.Fatal("object content changed")
		}
		ret, err := root.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: &bucket, Key: &key, VersionId: version})
		if err != nil {
			t.Fatalf("get object retention: %v", err)
		}
		if ret.Retention == nil || ret.Retention.Mode != types.ObjectLockRetentionModeCompliance ||
			ret.Retention.RetainUntilDate == nil || ret.Retention.RetainUntilDate.Before(retainUntil) {
			t.Fatalf("retention changed: %+v", ret.Retention)
		}
	})
}

func s3Client(t *testing.T, accessKey, secretKey string) *s3.Client {
	t.Helper()
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(stack.AuditS3Endpoint()),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	})
}

func mustSecret(t *testing.T, name string) string {
	t.Helper()
	v, err := stack.Secret(name)
	if err != nil {
		t.Fatalf("read secret %s (run `make dev-secrets up audit-bootstrap` first): %v", name, err)
	}
	return v
}

func expectError(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded; the WORM guarantee is broken", op)
	}
	t.Logf("%s rejected as expected: %v", op, err)
}
