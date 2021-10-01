package kms

import (
	"context"
	"fmt"
	"time"

	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/dcoker/biscuit/cmd/internal/flags"
	myAWS "github.com/dcoker/biscuit/internal/aws"
	"github.com/spf13/cobra"
)

func deprovisionCmd(ctx context.Context) *cobra.Command {
	regions := flags.CSV([]string{"us-east-1", "us-west-1", "us-west-2"})
	label := flags.NewRegex("^[a-zA-Z0-9_-]+$", "default")
	cmd := &cobra.Command{
		Use:   "deprovision",
		Short: "Deprovision AWS resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			l := label.String()
			rs := []string(regions)
			destructive, err := cmd.Flags().GetBool("destructive")
			if err != nil {
				return err
			}

			dep := &kmsDeprovision{
				label:       &l,
				regions:     &rs,
				destructive: &destructive,
			}

			return dep.Run(ctx)
		},
	}
	cmd.Flags().VarP(&regions, "regions", "r", "Comma-delimited list of regions to provision keys in. If the enviroment variable BISCUIT_REGIONS "+
		"is set, it will be used as the default value.")
	cmd.Flags().VarP(label, "label", "l",
		"Label for the keys created. This is used to uniquely identify the keys across regions. There can "+
			"be multiple labels in use within an AWS account. If the environment variable BISCUIT_LABEL "+
			"is set, it will be used as the default value")
	cmd.Flags().Bool("destructive", false,
		"If true, the resources for this label will actually be deleted.")
	return cmd
}

type kmsDeprovision struct {
	regions     *[]string
	label       *string
	destructive *bool
}

// Run the command.
func (w *kmsDeprovision) Run(ctx context.Context) error {
	var failure error
	var wg sync.WaitGroup
	for _, region := range *w.regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			if err := w.deprovisionOneRegion(ctx, region); err != nil {
				fmt.Fprintf(os.Stderr, "%s: error: %s\n", region, err)
				failure = err
			}
		}(region)
	}
	wg.Wait()

	if !*w.destructive {
		fmt.Printf("\nTo delete these resources, re-run this command with --destructive.\n")
	}
	return failure
}

func (w *kmsDeprovision) deprovisionOneRegion(ctx context.Context, region string) error {
	cfg := myAWS.MustNewConfig(ctx, config.WithRegion(region))
	aliasName := kmsAliasName(*w.label)
	stackName := cfStackName(*w.label)
	fmt.Printf("%s: Searching for label '%s'...\n", region, *w.label)
	kmsClient := kmsHelper{kms.NewFromConfig(cfg)}
	foundAlias, err := kmsClient.GetAliasByName(ctx, aliasName)
	if err != nil {
		return err
	}
	if foundAlias == nil {
		fmt.Printf("%s: No KMS Key Alias %s was found.\n", region, aliasName)
	} else {
		fmt.Printf("%s: Found alias %s for %s\n", region, aliasName, *foundAlias.TargetKeyId)
		if *w.destructive {
			fmt.Printf("%s: Deleting alias...\n", region)
			if _, err := kmsClient.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: foundAlias.AliasName}); err != nil {
				return err
			}
			fmt.Printf("%s: ... alias deleted.\n", region)
		}
	}

	exists, err := checkCloudFormationStackExists(ctx, stackName, region)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Printf("%s: No CloudFormation stack named %s was found.\n", region, stackName)
		return nil
	}
	fmt.Printf("%s: Found stack: %s\n", region, stackName)
	if *w.destructive {
		cfg := myAWS.MustNewConfig(ctx, config.WithRegion(region))
		cfclient := cloudformation.NewFromConfig(cfg)
		fmt.Printf("%s: Deleting CloudFormation stack. This may take a while...\n", region)
		if _, err := cfclient.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: &stackName}); err != nil {
			return err
		}
		waiter := cloudformation.NewStackDeleteCompleteWaiter(cfclient)
		if err := waiter.Wait(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName}, 2*time.Hour); err != nil {
			return err
		}
		fmt.Printf("%s: ... stack deleted.\n", region)
	}

	return nil
}
