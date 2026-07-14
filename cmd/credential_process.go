package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	multiSetName string
	multiSetFile string
)

func init() {
	initCredentialsSubCommand(credentialProcessCmd)
	credentialProcessCmd.PersistentFlags().StringVar(&multiSetName, "multi-set", "", "Name (iamra-name) of the multi-region failover set to use from the multi-set file")
	credentialProcessCmd.PersistentFlags().StringVar(&multiSetFile, "multi-set-file", "", "Path to the multi-set YAML file (default \"~/.aws/"+helper.DefaultMultiSetFileName+"\")")
	for _, flag := range []string{"trust-anchor-arn", "profile-arn", "role-arn", "region", "endpoint"} {
		credentialProcessCmd.MarkFlagsMutuallyExclusive("multi-set", flag)
	}
}

var credentialProcessCmd = &cobra.Command{
	Use:   "credential-process [flags]",
	Short: "Retrieve AWS credentials in the appropriate format for external credential processes",
	Long: `To retrieve AWS credentials in the appropriate format for external
credential processes, as determined by the SDK/CLI. More information can be
found at: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html`,
	Run: func(cmd *cobra.Command, args []string) {
		err := PopulateCredentialsOptions()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		helper.Debug = credentialsOptions.Debug

		signer, signingAlgorithm, err := helper.GetSigner(&credentialsOptions)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		defer signer.Close()

		var credentialProcessOutput helper.CredentialProcessOutput
		if multiSetName != "" {
			multiSetPath := multiSetFile
			if multiSetPath == "" {
				multiSetPath, err = helper.DefaultMultiSetFilePath()
				if err != nil {
					log.Println(err)
					os.Exit(1)
				}
			}
			multiSet, err := helper.LoadMultiSet(multiSetPath, multiSetName)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
			credentialProcessOutput, err = helper.GenerateCredentialsWithFailover(&credentialsOptions, signer, signingAlgorithm, multiSet)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		} else {
			if multiSetFile != "" {
				log.Println("--multi-set-file requires --multi-set")
				os.Exit(1)
			}
			credentialProcessOutput, err = helper.GenerateCredentials(&credentialsOptions, signer, signingAlgorithm)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}
		buf, _ := json.Marshal(credentialProcessOutput)
		fmt.Print(string(buf[:]))
	},
}
