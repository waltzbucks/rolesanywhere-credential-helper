package aws_signing_helper

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/smithy-go"
)

func writeMultiSetFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "iamra-multiset.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write multi-set file: %v", err)
	}
	return path
}

const validMultiSetYaml = `
- iamra-name: apn-failover
  account-id: 123456789012
  assume_role-arn: arn:aws:iam::123456789012:role/MyRole
  iamra-set:
  - trust-anchor-id: 11111111-1111-1111-1111-111111111111
    profile-id: 22222222-2222-2222-2222-222222222222
    region: ap-northeast-2
    default: true
  - trust-anchor-id: 33333333-3333-3333-3333-333333333333
    profile-id: 44444444-4444-4444-4444-444444444444
    region: ap-northeast-1
`

func TestLoadMultiSet(t *testing.T) {
	path := writeMultiSetFile(t, validMultiSetYaml)

	multiSet, err := LoadMultiSet(path, "apn-failover")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if multiSet.AccountId != "123456789012" {
		t.Errorf("account id = %q, want 123456789012", multiSet.AccountId)
	}
	if len(multiSet.IamraSet) != 2 {
		t.Fatalf("len(IamraSet) = %d, want 2", len(multiSet.IamraSet))
	}

	entries := orderedEntries(multiSet)
	if entries[0].Region != "ap-northeast-2" {
		t.Errorf("first entry region = %q, want ap-northeast-2 (the default entry)", entries[0].Region)
	}
	if entries[1].Region != "ap-northeast-1" {
		t.Errorf("second entry region = %q, want ap-northeast-1", entries[1].Region)
	}
}

func TestLoadMultiSetUnknownName(t *testing.T) {
	path := writeMultiSetFile(t, validMultiSetYaml)
	if _, err := LoadMultiSet(path, "does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown iamra-name")
	}
}

func TestLoadMultiSetRejectsUnknownKey(t *testing.T) {
	path := writeMultiSetFile(t, `
- iamra-name: apn-failover
  account-id: 123456789012
  assume_role-arn: arn:aws:iam::123456789012:role/MyRole
  iamra-set:
  - trust-anchor-id: 11111111-1111-1111-1111-111111111111
    profile-id: 22222222-2222-2222-2222-222222222222
    regoin: ap-northeast-2
`)
	if _, err := LoadMultiSet(path, "apn-failover"); err == nil {
		t.Fatal("expected an error for a typo'd key")
	}
}

func TestLoadMultiSetRejectsDuplicateDefault(t *testing.T) {
	path := writeMultiSetFile(t, `
- iamra-name: apn-failover
  account-id: 123456789012
  assume_role-arn: arn:aws:iam::123456789012:role/MyRole
  iamra-set:
  - trust-anchor-id: 11111111-1111-1111-1111-111111111111
    profile-id: 22222222-2222-2222-2222-222222222222
    region: ap-northeast-2
    default: true
  - trust-anchor-id: 33333333-3333-3333-3333-333333333333
    profile-id: 44444444-4444-4444-4444-444444444444
    region: ap-northeast-1
    default: true
`)
	if _, err := LoadMultiSet(path, "apn-failover"); err == nil {
		t.Fatal("expected an error for two entries marked default")
	}
}

func TestLoadMultiSetRejectsBadAccountId(t *testing.T) {
	path := writeMultiSetFile(t, `
- iamra-name: apn-failover
  account-id: 123
  assume_role-arn: arn:aws:iam::123456789012:role/MyRole
  iamra-set:
  - trust-anchor-id: 11111111-1111-1111-1111-111111111111
    profile-id: 22222222-2222-2222-2222-222222222222
    region: ap-northeast-2
`)
	if _, err := LoadMultiSet(path, "apn-failover"); err == nil {
		t.Fatal("expected an error for a non-12-digit account-id")
	}
}

func TestEntryArns(t *testing.T) {
	path := writeMultiSetFile(t, `
- iamra-name: cn-failover
  account-id: 123456789012
  assume_role-arn: arn:aws-cn:iam::123456789012:role/MyRole
  iamra-set:
  - trust-anchor-id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    profile-id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
    region: cn-north-1
`)
	multiSet, err := LoadMultiSet(path, "cn-failover")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assumeRoleArn, err := arn.Parse(multiSet.AssumeRoleArn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	trustAnchorArn, profileArn := entryArns(multiSet.IamraSet[0], multiSet.AccountId, assumeRoleArn)
	wantTrustAnchor := "arn:aws-cn:rolesanywhere:cn-north-1:123456789012:trust-anchor/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	wantProfile := "arn:aws-cn:rolesanywhere:cn-north-1:123456789012:profile/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if trustAnchorArn != wantTrustAnchor {
		t.Errorf("trust anchor arn = %q, want %q", trustAnchorArn, wantTrustAnchor)
	}
	if profileArn != wantProfile {
		t.Errorf("profile arn = %q, want %q", profileArn, wantProfile)
	}
}

func TestIsRetryableCreateSessionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"throttling", &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}, true},
		{"network", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"dns not found", &net.DNSError{Err: "no such host", Name: "rolesanywhere.ap-northeast-9.amazonaws.com", IsNotFound: true}, true},
		{"access denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "Invalid or empty profile provided."}, false},
		{"validation", &smithy.GenericAPIError{Code: "ValidationException", Message: "bad input"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableCreateSessionError(tc.err); got != tc.want {
				t.Errorf("isRetryableCreateSessionError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
