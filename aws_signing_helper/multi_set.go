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

const DefaultMultiSetFileName = "iamra-multiset.yaml"

var accountIdPattern = regexp.MustCompile(`^[0-9]{12}$`)

// yamlString accepts both quoted and unquoted YAML scalars (e.g. a bare
// 123456789012 account id, which YAML would otherwise decode as an integer)
// and preserves the raw text, including leading zeros.
type yamlString string

func (s *yamlString) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: expected a scalar value", value.Line)
	}
	*s = yamlString(value.Value)
	return nil
}

// MultiSetEntry is one regional trust anchor/profile pair within a MultiSet.
type MultiSetEntry struct {
	TrustAnchorId string `yaml:"trust-anchor-id"`
	ProfileId     string `yaml:"profile-id"`
	Region        string `yaml:"region"`
	Default       bool   `yaml:"default"`
}

// MultiSet is a named group of regional Roles Anywhere resources that all
// map to the same role, used to fail over between regions on retryable
// CreateSession errors (throttling, 5xx, network).
type MultiSet struct {
	Name          string          `yaml:"iamra-name"`
	AccountId     yamlString      `yaml:"account-id"`
	AssumeRoleArn string          `yaml:"assume_role-arn"`
	IamraSet      []MultiSetEntry `yaml:"iamra-set"`

	partition string
}

// DefaultMultiSetFilePath returns ~/.aws/iamra-multiset.yaml, mirroring the
// location of the AWS CLI configuration files.
func DefaultMultiSetFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to locate home directory for the default multi-set file: %w", err)
	}
	return filepath.Join(homeDir, ".aws", DefaultMultiSetFileName), nil
}

// LoadMultiSet reads the multi-set YAML file at path and returns the
// validated entry whose iamra-name matches name.
func LoadMultiSet(path string, name string) (*MultiSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read multi-set file: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var multiSets []MultiSet
	if err := decoder.Decode(&multiSets); err != nil {
		return nil, fmt.Errorf("unable to parse multi-set file '%s': %w", path, err)
	}

	var names []string
	for i := range multiSets {
		if multiSets[i].Name == name {
			multiSet := multiSets[i]
			if err := multiSet.validate(); err != nil {
				return nil, fmt.Errorf("invalid multi-set '%s' in '%s': %w", name, path, err)
			}
			return &multiSet, nil
		}
		names = append(names, multiSets[i].Name)
	}
	return nil, fmt.Errorf("multi-set '%s' not found in '%s' (available: %v)", name, path, names)
}

func (m *MultiSet) validate() error {
	if !accountIdPattern.MatchString(string(m.AccountId)) {
		return fmt.Errorf("account-id '%s' must be a 12-digit AWS account id", m.AccountId)
	}
	roleArn, err := arn.Parse(m.AssumeRoleArn)
	if err != nil {
		return fmt.Errorf("invalid assume_role-arn '%s': %w", m.AssumeRoleArn, err)
	}
	m.partition = roleArn.Partition
	if len(m.IamraSet) == 0 {
		return errors.New("iamra-set must contain at least one entry")
	}
	defaultCount := 0
	for i, entry := range m.IamraSet {
		if entry.TrustAnchorId == "" || entry.ProfileId == "" || entry.Region == "" {
			return fmt.Errorf("iamra-set entry #%d must set trust-anchor-id, profile-id, and region", i+1)
		}
		if entry.Default {
			defaultCount++
		}
	}
	if defaultCount > 1 {
		return errors.New("iamra-set must mark at most one entry as default")
	}
	return nil
}

// orderedEntries returns the entries in attempt order: the default entry (if
// any) first, followed by the remaining entries in file order.
func (m *MultiSet) orderedEntries() []MultiSetEntry {
	ordered := make([]MultiSetEntry, 0, len(m.IamraSet))
	for _, entry := range m.IamraSet {
		if entry.Default {
			ordered = append(ordered, entry)
		}
	}
	for _, entry := range m.IamraSet {
		if !entry.Default {
			ordered = append(ordered, entry)
		}
	}
	return ordered
}

// credentialsOptsFor clones the base options and fills in the ARNs and region
// for one regional attempt. GenerateCredentials mutates its options, so each
// attempt must get its own copy.
func (m *MultiSet) credentialsOptsFor(entry MultiSetEntry, base *CredentialsOpts) CredentialsOpts {
	opts := *base
	opts.RoleArn = m.AssumeRoleArn
	opts.TrustAnchorArnStr = fmt.Sprintf("arn:%s:rolesanywhere:%s:%s:trust-anchor/%s", m.partition, entry.Region, m.AccountId, entry.TrustAnchorId)
	opts.ProfileArnStr = fmt.Sprintf("arn:%s:rolesanywhere:%s:%s:profile/%s", m.partition, entry.Region, m.AccountId, entry.ProfileId)
	opts.Region = entry.Region
	return opts
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
// Everything else (AccessDenied, validation, resource-not-found, ...) is a
// configuration problem that the next region would only reproduce or mask,
// so it must not trigger failover.
var createSessionRetryables = retry.IsErrorRetryables(append(
	[]retry.IsErrorRetryable{retryableDNSError{}},
	retry.DefaultRetryables...,
))

// IsRetryableCreateSessionError reports whether a CreateSession failure is
// worth retrying against another region's trust anchor/profile pair.
func IsRetryableCreateSessionError(err error) bool {
	return createSessionRetryables.IsErrorRetryable(err) == aws.TrueTernary
}

type generateCredentialsFunc func(*CredentialsOpts, Signer, string) (CredentialProcessOutput, error)

// GenerateCredentialsWithFailover tries CreateSession against each entry of
// the multi-set in order (default entry first) and returns the first
// successful result. Retryable errors move on to the next entry;
// non-retryable errors abort immediately.
func GenerateCredentialsWithFailover(opts *CredentialsOpts, signer Signer, signatureAlgorithm string, multiSet *MultiSet) (CredentialProcessOutput, error) {
	return generateCredentialsWithFailover(opts, signer, signatureAlgorithm, multiSet, GenerateCredentials)
}

func generateCredentialsWithFailover(opts *CredentialsOpts, signer Signer, signatureAlgorithm string, multiSet *MultiSet, generate generateCredentialsFunc) (CredentialProcessOutput, error) {
	entries := multiSet.orderedEntries()
	var lastErr error
	for i, entry := range entries {
		attemptOpts := multiSet.credentialsOptsFor(entry, opts)
		output, err := generate(&attemptOpts, signer, signatureAlgorithm)
		if err == nil {
			if i > 0 {
				log.Printf("multi-set '%s': CreateSession succeeded in region %s after failover", multiSet.Name, entry.Region)
			}
			return output, nil
		}
		lastErr = err
		if !IsRetryableCreateSessionError(err) {
			return CredentialProcessOutput{}, fmt.Errorf("multi-set '%s': CreateSession in region %s failed with non-retryable error: %w", multiSet.Name, entry.Region, err)
		}
		if i < len(entries)-1 {
			log.Printf("multi-set '%s': CreateSession in region %s failed with retryable error, trying next entry: %v", multiSet.Name, entry.Region, err)
		}
	}
	return CredentialProcessOutput{}, fmt.Errorf("multi-set '%s': all %d entries failed, last error: %w", multiSet.Name, len(entries), lastErr)
}
