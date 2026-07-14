package aws_signing_helper

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"gopkg.in/yaml.v3"
)

// DefaultMultiSetFileName is the file name of the multi-set file within the
// user's AWS config directory, used when --multi-set-file isn't specified.
const DefaultMultiSetFileName = "iamra-multiset.yaml"

var accountIdRegex = regexp.MustCompile(`^[0-9]{12}$`)

// IamraSetEntry is a single region's trust anchor/profile pair within an
// IamraMultiSet.
type IamraSetEntry struct {
	TrustAnchorId string `yaml:"trust-anchor-id"`
	ProfileId     string `yaml:"profile-id"`
	Region        string `yaml:"region"`
	Default       bool   `yaml:"default"`
}

// IamraMultiSet is one named group of region-specific trust anchor/profile
// sets, tried in order (default entry first) until one succeeds.
type IamraMultiSet struct {
	IamraName     string          `yaml:"iamra-name"`
	AccountId     string          `yaml:"account-id"`
	AssumeRoleArn string          `yaml:"assume_role-arn"`
	IamraSet      []IamraSetEntry `yaml:"iamra-set"`
}

// rawIamraSetEntry/rawIamraMultiSet decode with yaml.Node values so that
// unrecognized keys can be rejected and an unquoted account-id (parsed by
// YAML as an integer) can be accepted without silently truncating it.
type rawIamraSetEntry struct {
	TrustAnchorId yaml.Node `yaml:"trust-anchor-id"`
	ProfileId     yaml.Node `yaml:"profile-id"`
	Region        yaml.Node `yaml:"region"`
	Default       yaml.Node `yaml:"default"`
}

func (e *rawIamraSetEntry) UnmarshalYAML(node *yaml.Node) error {
	type plain rawIamraSetEntry
	if err := node.Decode((*plain)(e)); err != nil {
		return err
	}
	return rejectUnknownKeys(node, "trust-anchor-id", "profile-id", "region", "default")
}

type rawIamraMultiSet struct {
	IamraName     yaml.Node          `yaml:"iamra-name"`
	AccountId     yaml.Node          `yaml:"account-id"`
	AssumeRoleArn yaml.Node          `yaml:"assume_role-arn"`
	IamraSet      []rawIamraSetEntry `yaml:"iamra-set"`
}

func (m *rawIamraMultiSet) UnmarshalYAML(node *yaml.Node) error {
	type plain rawIamraMultiSet
	if err := node.Decode((*plain)(m)); err != nil {
		return err
	}
	return rejectUnknownKeys(node, "iamra-name", "account-id", "assume_role-arn", "iamra-set")
}

// rejectUnknownKeys returns an error if the mapping node contains a key not
// present in allowed. This catches typos in the multi-set file (e.g.
// "trust-anchor-id" misspelled) that would otherwise be silently ignored.
func rejectUnknownKeys(node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected a YAML mapping, got %v", node.Kind)
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = true
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if !allowedSet[key] {
			return fmt.Errorf("unknown key %q at line %d", key, node.Content[i].Line)
		}
	}
	return nil
}

// scalarString decodes a YAML scalar node to its string form, whether it was
// written quoted (already a string) or unquoted (e.g. an integer like
// account-id: 123456789012).
func scalarString(node yaml.Node) (string, bool) {
	if node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return "", false
	}
	return node.Value, true
}

func scalarBool(node yaml.Node) (bool, error) {
	if node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return false, nil
	}
	var b bool
	if err := node.Decode(&b); err != nil {
		return false, fmt.Errorf("invalid boolean at line %d: %w", node.Line, err)
	}
	return b, nil
}

// LoadMultiSet reads the multi-set YAML file at path and returns the entry
// whose iamra-name matches name.
func LoadMultiSet(path string, name string) (IamraMultiSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return IamraMultiSet{}, fmt.Errorf("unable to read multi-set file '%s': %w", path, err)
	}

	var rawSets []rawIamraMultiSet
	if err := yaml.Unmarshal(data, &rawSets); err != nil {
		return IamraMultiSet{}, fmt.Errorf("unable to parse multi-set file '%s': %w", path, err)
	}

	for _, rawSet := range rawSets {
		iamraName, ok := scalarString(rawSet.IamraName)
		if !ok || iamraName != name {
			continue
		}
		return parseMultiSet(rawSet)
	}

	return IamraMultiSet{}, fmt.Errorf("no multi-set named '%s' found in '%s'", name, path)
}

func parseMultiSet(rawSet rawIamraMultiSet) (IamraMultiSet, error) {
	iamraName, _ := scalarString(rawSet.IamraName)

	accountId, ok := scalarString(rawSet.AccountId)
	if !ok {
		return IamraMultiSet{}, fmt.Errorf("multi-set '%s': missing account-id", iamraName)
	}
	if !accountIdRegex.MatchString(accountId) {
		return IamraMultiSet{}, fmt.Errorf("multi-set '%s': account-id must be exactly 12 digits", iamraName)
	}

	assumeRoleArnStr, ok := scalarString(rawSet.AssumeRoleArn)
	if !ok {
		return IamraMultiSet{}, fmt.Errorf("multi-set '%s': missing assume_role-arn", iamraName)
	}
	if _, err := arn.Parse(assumeRoleArnStr); err != nil {
		return IamraMultiSet{}, fmt.Errorf("multi-set '%s': invalid assume_role-arn: %w", iamraName, err)
	}

	if len(rawSet.IamraSet) == 0 {
		return IamraMultiSet{}, fmt.Errorf("multi-set '%s': iamra-set must contain at least one entry", iamraName)
	}

	multiSet := IamraMultiSet{
		IamraName:     iamraName,
		AccountId:     accountId,
		AssumeRoleArn: assumeRoleArnStr,
	}

	defaultSeen := false
	for i, rawEntry := range rawSet.IamraSet {
		trustAnchorId, ok := scalarString(rawEntry.TrustAnchorId)
		if !ok {
			return IamraMultiSet{}, fmt.Errorf("multi-set '%s': entry %d: missing trust-anchor-id", iamraName, i)
		}
		profileId, ok := scalarString(rawEntry.ProfileId)
		if !ok {
			return IamraMultiSet{}, fmt.Errorf("multi-set '%s': entry %d: missing profile-id", iamraName, i)
		}
		region, ok := scalarString(rawEntry.Region)
		if !ok {
			return IamraMultiSet{}, fmt.Errorf("multi-set '%s': entry %d: missing region", iamraName, i)
		}
		isDefault, err := scalarBool(rawEntry.Default)
		if err != nil {
			return IamraMultiSet{}, fmt.Errorf("multi-set '%s': entry %d: %w", iamraName, i, err)
		}
		if isDefault {
			if defaultSeen {
				return IamraMultiSet{}, fmt.Errorf("multi-set '%s': more than one entry marked default", iamraName)
			}
			defaultSeen = true
		}

		multiSet.IamraSet = append(multiSet.IamraSet, IamraSetEntry{
			TrustAnchorId: trustAnchorId,
			ProfileId:     profileId,
			Region:        region,
			Default:       isDefault,
		})
	}

	return multiSet, nil
}

// DefaultMultiSetFilePath returns "~/.aws/iamra-multiset.yaml".
func DefaultMultiSetFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}
	return filepath.Join(homeDir, ".aws", DefaultMultiSetFileName), nil
}

// orderedEntries returns the multi-set's entries with the default entry (if
// any) moved to the front, otherwise in file order.
func orderedEntries(multiSet IamraMultiSet) []IamraSetEntry {
	entries := make([]IamraSetEntry, 0, len(multiSet.IamraSet))
	var defaultEntry *IamraSetEntry
	for i := range multiSet.IamraSet {
		if multiSet.IamraSet[i].Default {
			defaultEntry = &multiSet.IamraSet[i]
			continue
		}
		entries = append(entries, multiSet.IamraSet[i])
	}
	if defaultEntry != nil {
		entries = append([]IamraSetEntry{*defaultEntry}, entries...)
	}
	return entries
}

// entryArns builds the trust anchor and profile ARNs for entry, using
// accountId and the partition parsed from assumeRoleArn (trust anchor and
// profile ARNs always share the caller's partition).
func entryArns(entry IamraSetEntry, accountId string, assumeRoleArn arn.ARN) (trustAnchorArn string, profileArn string) {
	trustAnchorArn = fmt.Sprintf("arn:%s:rolesanywhere:%s:%s:trust-anchor/%s", assumeRoleArn.Partition, entry.Region, accountId, entry.TrustAnchorId)
	profileArn = fmt.Sprintf("arn:%s:rolesanywhere:%s:%s:profile/%s", assumeRoleArn.Partition, entry.Region, accountId, entry.ProfileId)
	return trustAnchorArn, profileArn
}

// retryableDNSError treats any DNS failure as retryable. The SDK's
// RetryableConnectionError deliberately refuses to retry NXDOMAIN against the
// same endpoint, but for cross-region failover an unresolvable regional
// endpoint is exactly the signal to try the next region.
type retryableDNSError struct{}

func (retryableDNSError) IsErrorRetryable(err error) aws.Ternary {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return aws.TrueTernary
	}
	return aws.UnknownTernary
}

// createSessionRetryables mirrors the SDK's standard retryer classification
// (retry.DefaultRetryables: connection-level failures, retryable/throttling
// API error codes, and retryable HTTP status codes), plus retryableDNSError.
// Everything else (AccessDenied, validation, resource-not-found, malformed
// input, etc.) is a configuration error that failover would only reproduce
// or mask, so it must not trigger failover.
var createSessionRetryables = retry.IsErrorRetryables(append(
	[]retry.IsErrorRetryable{retryableDNSError{}},
	retry.DefaultRetryables...,
))

func isRetryableCreateSessionError(err error) bool {
	return createSessionRetryables.IsErrorRetryable(err) == aws.TrueTernary
}

// GenerateCredentialsWithFailover tries CreateSession against each entry in
// multiSet in order (default entry first), moving on to the next entry only
// when the error is classified as retryable. A non-retryable error (e.g.
// AccessDeniedException from a misconfigured ARN) is returned immediately
// without trying the remaining entries. The role ARN is taken from the
// multi-set's assume_role-arn, not from opts.
func GenerateCredentialsWithFailover(opts *CredentialsOpts, signer Signer, signatureAlgorithm string, multiSet IamraMultiSet) (CredentialProcessOutput, error) {
	// Already validated by LoadMultiSet, so this parse cannot fail
	assumeRoleArn, err := arn.Parse(multiSet.AssumeRoleArn)
	if err != nil {
		return CredentialProcessOutput{}, fmt.Errorf("failed to parse assume_role-arn: '%w'", err)
	}

	entries := orderedEntries(multiSet)
	var lastErr error
	for i, entry := range entries {
		trustAnchorArn, profileArn := entryArns(entry, multiSet.AccountId, assumeRoleArn)

		attemptOpts := *opts
		attemptOpts.RoleArn = multiSet.AssumeRoleArn
		attemptOpts.TrustAnchorArnStr = trustAnchorArn
		attemptOpts.ProfileArnStr = profileArn
		attemptOpts.Region = ""
		attemptOpts.Endpoint = ""

		output, err := GenerateCredentials(&attemptOpts, signer, signatureAlgorithm)
		if err == nil {
			return output, nil
		}

		lastErr = err
		if !isRetryableCreateSessionError(err) {
			return CredentialProcessOutput{}, err
		}
		log.Printf("multi-set '%s': attempt %d/%d (region %s) failed with a retryable error, trying next entry: %v", multiSet.IamraName, i+1, len(entries), entry.Region, err)
	}

	return CredentialProcessOutput{}, fmt.Errorf("all %d entries in multi-set '%s' failed, last error: %w", len(entries), multiSet.IamraName, lastErr)
}
