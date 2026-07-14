package aws_signing_helper

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

const testMultiSetYaml = `- iamra-name: apn-failover
  account-id: 123456789012
  assume_role-arn: arn:aws:iam::123456789012:role/test-role
  iamra-set:
  - trust-anchor-id: apn2-ta-id
    profile-id: apn2-prof-id
    region: ap-northeast-2
    default: true
  - trust-anchor-id: apn1-ta-id
    profile-id: apn1-prof-id
    region: ap-northeast-1
  - trust-anchor-id: apn3-ta-id
    profile-id: apn3-prof-id
    region: ap-northeast-3
- iamra-name: other-set
  account-id: "210987654321"
  assume_role-arn: arn:aws-cn:iam::210987654321:role/cn-role
  iamra-set:
  - trust-anchor-id: cn-ta-id
    profile-id: cn-prof-id
    region: cn-north-1
`

func writeMultiSetFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), DefaultMultiSetFileName)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMultiSet(t *testing.T) {
	path := writeMultiSetFile(t, testMultiSetYaml)

	multiSet, err := LoadMultiSet(path, "apn-failover")
	if err != nil {
		t.Fatal(err)
	}
	// Unquoted account-id must survive as a string.
	if string(multiSet.AccountId) != "123456789012" {
		t.Errorf("unexpected account id: %s", multiSet.AccountId)
	}
	if multiSet.AssumeRoleArn != "arn:aws:iam::123456789012:role/test-role" {
		t.Errorf("unexpected role arn: %s", multiSet.AssumeRoleArn)
	}
	if len(multiSet.IamraSet) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(multiSet.IamraSet))
	}

	// Quoted account-id and non-aws partition.
	otherSet, err := LoadMultiSet(path, "other-set")
	if err != nil {
		t.Fatal(err)
	}
	opts := otherSet.credentialsOptsFor(otherSet.IamraSet[0], &CredentialsOpts{})
	wantTrustAnchorArn := "arn:aws-cn:rolesanywhere:cn-north-1:210987654321:trust-anchor/cn-ta-id"
	if opts.TrustAnchorArnStr != wantTrustAnchorArn {
		t.Errorf("trust anchor arn: got %s, want %s", opts.TrustAnchorArnStr, wantTrustAnchorArn)
	}
}

func TestLoadMultiSetNameNotFound(t *testing.T) {
	path := writeMultiSetFile(t, testMultiSetYaml)
	_, err := LoadMultiSet(path, "no-such-set")
	if err == nil || !strings.Contains(err.Error(), "apn-failover") {
		t.Errorf("expected not-found error listing available names, got: %v", err)
	}
}

func TestLoadMultiSetValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			"bad account id",
			"- iamra-name: s\n  account-id: 123\n  assume_role-arn: arn:aws:iam::123456789012:role/r\n  iamra-set:\n  - trust-anchor-id: t\n    profile-id: p\n    region: us-east-1\n",
			"12-digit",
		},
		{
			"bad role arn",
			"- iamra-name: s\n  account-id: 123456789012\n  assume_role-arn: not-an-arn\n  iamra-set:\n  - trust-anchor-id: t\n    profile-id: p\n    region: us-east-1\n",
			"assume_role-arn",
		},
		{
			"empty iamra-set",
			"- iamra-name: s\n  account-id: 123456789012\n  assume_role-arn: arn:aws:iam::123456789012:role/r\n  iamra-set: []\n",
			"at least one entry",
		},
		{
			"missing entry field",
			"- iamra-name: s\n  account-id: 123456789012\n  assume_role-arn: arn:aws:iam::123456789012:role/r\n  iamra-set:\n  - trust-anchor-id: t\n    region: us-east-1\n",
			"entry #1",
		},
		{
			"multiple defaults",
			"- iamra-name: s\n  account-id: 123456789012\n  assume_role-arn: arn:aws:iam::123456789012:role/r\n  iamra-set:\n  - trust-anchor-id: t\n    profile-id: p\n    region: us-east-1\n    default: true\n  - trust-anchor-id: t2\n    profile-id: p2\n    region: us-east-2\n    default: true\n",
			"at most one entry as default",
		},
		{
			"unknown field",
			"- iamra-name: s\n  account-id: 123456789012\n  assume_role-arn: arn:aws:iam::123456789012:role/r\n  iamra-set:\n  - trust-anchor-id: t\n    profile-id: p\n    region: us-east-1\n    defualt: true\n",
			"defualt",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeMultiSetFile(t, c.yaml)
			_, err := LoadMultiSet(path, "s")
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("expected error containing %q, got: %v", c.wantErr, err)
			}
		})
	}
}

func TestMultiSetOrderedEntries(t *testing.T) {
	yamlContent := `- iamra-name: s
  account-id: 123456789012
  assume_role-arn: arn:aws:iam::123456789012:role/r
  iamra-set:
  - trust-anchor-id: t1
    profile-id: p1
    region: ap-northeast-1
  - trust-anchor-id: t2
    profile-id: p2
    region: ap-northeast-2
    default: true
  - trust-anchor-id: t3
    profile-id: p3
    region: ap-northeast-3
`
	path := writeMultiSetFile(t, yamlContent)
	multiSet, err := LoadMultiSet(path, "s")
	if err != nil {
		t.Fatal(err)
	}
	var regions []string
	for _, entry := range multiSet.orderedEntries() {
		regions = append(regions, entry.Region)
	}
	want := []string{"ap-northeast-2", "ap-northeast-1", "ap-northeast-3"}
	if fmt.Sprint(regions) != fmt.Sprint(want) {
		t.Errorf("attempt order: got %v, want %v", regions, want)
	}
}

func TestMultiSetCredentialsOptsFor(t *testing.T) {
	path := writeMultiSetFile(t, testMultiSetYaml)
	multiSet, err := LoadMultiSet(path, "apn-failover")
	if err != nil {
		t.Fatal(err)
	}
	base := CredentialsOpts{SessionDuration: 1800, Debug: true, Region: "should-be-replaced"}
	opts := multiSet.credentialsOptsFor(multiSet.IamraSet[1], &base)

	if opts.TrustAnchorArnStr != "arn:aws:rolesanywhere:ap-northeast-1:123456789012:trust-anchor/apn1-ta-id" {
		t.Errorf("unexpected trust anchor arn: %s", opts.TrustAnchorArnStr)
	}
	if opts.ProfileArnStr != "arn:aws:rolesanywhere:ap-northeast-1:123456789012:profile/apn1-prof-id" {
		t.Errorf("unexpected profile arn: %s", opts.ProfileArnStr)
	}
	if opts.RoleArn != "arn:aws:iam::123456789012:role/test-role" {
		t.Errorf("unexpected role arn: %s", opts.RoleArn)
	}
	if opts.Region != "ap-northeast-1" {
		t.Errorf("unexpected region: %s", opts.Region)
	}
	if opts.SessionDuration != 1800 || !opts.Debug {
		t.Error("base options were not carried over")
	}
	if base.Region != "should-be-replaced" {
		t.Error("base options must not be mutated")
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
		{"dns not found", fmt.Errorf("request send failed: %w", &net.DNSError{Err: "no such host", Name: "rolesanywhere.ap-northeast-9.amazonaws.com", IsNotFound: true}), true},
		{"access denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "Invalid or empty profile provided."}, false},
		{"validation", &smithy.GenericAPIError{Code: "ValidationException", Message: "bad input"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsRetryableCreateSessionError(c.err); got != c.want {
				t.Errorf("IsRetryableCreateSessionError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestGenerateCredentialsWithFailover(t *testing.T) {
	path := writeMultiSetFile(t, testMultiSetYaml)
	multiSet, err := LoadMultiSet(path, "apn-failover")
	if err != nil {
		t.Fatal(err)
	}
	throttled := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "Invalid or empty profile provided."}
	success := CredentialProcessOutput{Version: 1, AccessKeyId: "AKID"}

	t.Run("failover to next region on retryable error", func(t *testing.T) {
		var attempts []string
		generate := func(opts *CredentialsOpts, signer Signer, alg string) (CredentialProcessOutput, error) {
			attempts = append(attempts, opts.Region)
			if opts.Region == "ap-northeast-2" {
				return CredentialProcessOutput{}, throttled
			}
			return success, nil
		}
		output, err := generateCredentialsWithFailover(&CredentialsOpts{}, nil, "", multiSet, generate)
		if err != nil {
			t.Fatal(err)
		}
		if output.AccessKeyId != "AKID" {
			t.Errorf("unexpected output: %+v", output)
		}
		want := []string{"ap-northeast-2", "ap-northeast-1"}
		if fmt.Sprint(attempts) != fmt.Sprint(want) {
			t.Errorf("attempts: got %v, want %v", attempts, want)
		}
	})

	t.Run("non-retryable error aborts immediately", func(t *testing.T) {
		var attempts int
		generate := func(opts *CredentialsOpts, signer Signer, alg string) (CredentialProcessOutput, error) {
			attempts++
			return CredentialProcessOutput{}, denied
		}
		_, err := generateCredentialsWithFailover(&CredentialsOpts{}, nil, "", multiSet, generate)
		if err == nil || !strings.Contains(err.Error(), "non-retryable") {
			t.Errorf("expected non-retryable error, got: %v", err)
		}
		if !errors.Is(err, error(denied)) && !strings.Contains(err.Error(), "AccessDeniedException") {
			t.Errorf("original error not preserved: %v", err)
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("all entries exhausted", func(t *testing.T) {
		var attempts int
		generate := func(opts *CredentialsOpts, signer Signer, alg string) (CredentialProcessOutput, error) {
			attempts++
			return CredentialProcessOutput{}, throttled
		}
		_, err := generateCredentialsWithFailover(&CredentialsOpts{}, nil, "", multiSet, generate)
		if err == nil || !strings.Contains(err.Error(), "all 3 entries failed") {
			t.Errorf("expected exhaustion error, got: %v", err)
		}
		if attempts != 3 {
			t.Errorf("expected 3 attempts, got %d", attempts)
		}
	})
}
