package cmd

import (
	"errors"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	multiSetName string
	multiSetFile string
)

// Registers the --multi-set/--multi-set-file flags on a subcommand that vends
// credentials, marking them mutually exclusive with the single-region flags
// they replace.
func initMultiSetFlags(subCmd *cobra.Command) {
	subCmd.PersistentFlags().StringVar(&multiSetName, "multi-set", "", "Name (iamra-name) of a multi-region "+
		"failover set defined in the multi-set file. When set, the role ARN, trust anchor ARN, profile ARN, and region "+
		"for each attempt are taken from the selected set instead of "+
		"--role-arn/--trust-anchor-arn/--profile-arn/--region/--endpoint. "+
		"The entry marked \"default: true\" (or the first entry) is tried first; on a retryable error "+
		"(throttling, HTTP 5xx, network/DNS failure) the remaining entries are tried in file order. A non-retryable "+
		"error (e.g. AccessDeniedException) fails immediately without trying the remaining entries")
	subCmd.PersistentFlags().StringVar(&multiSetFile, "multi-set-file", "", "Path to the multi-set YAML file "+
		"used by --multi-set (default \"~/.aws/"+helper.DefaultMultiSetFileName+"\")")

	for _, flag := range []string{"role-arn", "trust-anchor-arn", "profile-arn", "region", "endpoint"} {
		subCmd.MarkFlagsMutuallyExclusive("multi-set", flag)
	}
}

// resolveMultiSet loads the multi-set selected by the --multi-set flag, or
// returns nil if the flag wasn't provided.
func resolveMultiSet() (*helper.MultiSet, error) {
	if multiSetName == "" {
		if multiSetFile != "" {
			return nil, errors.New("--multi-set-file requires --multi-set")
		}
		return nil, nil
	}
	multiSetPath := multiSetFile
	if multiSetPath == "" {
		var err error
		multiSetPath, err = helper.DefaultMultiSetFilePath()
		if err != nil {
			return nil, err
		}
	}
	return helper.LoadMultiSet(multiSetPath, multiSetName)
}
