package kms

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/dcoker/biscuit/algorithms"
	"github.com/dcoker/biscuit/algorithms/secretbox"
	"github.com/dcoker/biscuit/cmd/internal/assets"
	"github.com/dcoker/biscuit/cmd/internal/flags"
	myAWS "github.com/dcoker/biscuit/internal/aws"
	"github.com/dcoker/biscuit/internal/aws/arn"
	stringsFunc "github.com/dcoker/biscuit/internal/strings"
	"github.com/dcoker/biscuit/keymanager"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
)

var (
	arnDetailsMessage = "Users may be referenced by their naked username (ex: 'jeff') or prefixed with user/ (ex:" +
		" 'user/jeff'). Roles may be prefixed with role/ (ex: 'role/webserver'). When the naked or " +
		"prefixed forms are used, the full ARN is composed by using the account ID of the user " +
		"invoking the command. Principals prefixed with arn: are passed to AWS verbatim."
)

func initCmd(ctx context.Context) *cobra.Command {
	var filename string
	algo := flags.NewEnum(algorithms.GetRegisteredAlgorithmsNames(), secretbox.Name)
	template := assets.Must("data/awskms-key.template")
	regions := flags.CSV([]string{"us-east-1", "us-west-1", "us-west-2"})
	label := flags.NewRegex("^[a-zA-Z0-9_-]+$", "default")
	adminstrators := flags.CSV{}
	users := flags.CSV{}
	cloudformationTemplateURL := flags.URL{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initializes or updates a file with key configuration for use with AWS KMS",
		Long:  assets.Must("data/kmsinit.txt"),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for k, v := range map[string]string{
				"filename": filename,
			} {
				if v == "" {
					return fmt.Errorf("flag %s marked as required", k)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("algo", algo)
			// label := viper.GetString("label")
			// filename := viper.GetString("filename")
			l := label.String()
			algorithm := algo.String()
			createSimpleRoles, err := cmd.Flags().GetBool("create-simple-roles")
			if err != nil {
				return err
			}
			disableIAM, err := cmd.Flags().GetBool("disable-iam-policies")
			if err != nil {
				return err
			}
			createMissingKeys, err := cmd.Flags().GetBool("create-missing-keys")
			if err != nil {
				return err
			}

			fmt.Println("Label is", l)
			fmt.Println("createSimpleRoles", createSimpleRoles)
			fmt.Println("disableIAMKeys", disableIAM)
			fmt.Println("filename", filename)
			fmt.Println("algorithm", algorithm)
			fmt.Println("TemaplateURL", cloudformationTemplateURL)
			rs := []string(regions)
			admins := adminstrators.String()
			users := users.String()
			cfTemplate := cloudformationTemplateURL.String()
			init := &kmsInit{
				regions:                   &rs,
				label:                     &l,
				createMissingKeys:         &createMissingKeys,
				createSimpleRoles:         &createSimpleRoles,
				disableIam:                &disableIAM,
				administratorArns:         &admins,
				userArns:                  &users,
				filename:                  &filename,
				algorithm:                 &algorithm,
				cloudformationTemplateURL: &cfTemplate,
				keyCloudformationTemplate: template,
			}
			return init.Run(ctx)

		},
	}
	cmd.Flags().VarP(&regions, "regions", "r", "Comma-delimited list of regions to provision keys in. If the enviroment variable BISCUIT_REGIONS "+
		"is set, it will be used as the default value.")

	cmd.Flags().VarP(label, "label", "l",
		"Label for the keys created. This is used to uniquely identify the keys across regions. There can "+
			"be multiple labels in use within an AWS account. If the environment variable BISCUIT_LABEL "+
			"is set, it will be used as the default value")

	cmd.Flags().Bool("create-simple-roles", false,
		"Create simplified roles that are a allowed full encrypt or decrypt privileges under the created keys. "+
			"Note that this requires sufficient IAM privileges to call iam:CreateRole")

	cmd.Flags().Bool("create-missing-keys", false,
		"Provision regions that are not already configured for the speccified label")

	cmd.Flags().VarP(&adminstrators, "administrators", "d",
		"Comma-delimited list of IAM users, IAM roles, and AWS services ARNs that will "+
			"have administration privileges in the key policy attached to the new keys "+arnDetailsMessage)

	cmd.Flags().VarP(&users, "users", "u",
		"Comma-delimited list of IAM users, IAM roles, and AWS services ARNs that will have "+
			"user privileges in the key policy attached to the new keys "+arnDetailsMessage)

	cmd.Flags().Bool("disable-iam-policies", false,
		"Create KMS keys that will not evaluate IAM policies. If disabled, only the Key Policy document will "+
			"be evaluated when KMS authorizes API calls. Note that using this setting will prevent the "+
			"root account from accessing this key, and can require contacting AWS support for resolving "+
			"configuration problems")

	cmd.Flags().Var(&cloudformationTemplateURL, "cloudformation-template-url",
		"Full URL to the CloudFormation template to use. This overrides the built-in template.")

	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")

	cmd.Flags().VarP(algo, "algorithm", "a", "Encryption algorithm. If the environment variable BISCUIT_ALGORITHM is "+
		"set, it will be used as the default value. Options: "+
		strings.Join(algorithms.GetRegisteredAlgorithmsNames(), ", "),
	)

	return cmd
}

type kmsInit struct {
	regions           *[]string
	label             *string
	createMissingKeys *bool
	createSimpleRoles *bool
	disableIam        *bool
	administratorArns,
	userArns,
	filename,
	algorithm,
	cloudformationTemplateURL *string
	keyCloudformationTemplate string
}

// Run runs the command.
func (w *kmsInit) Run(ctx context.Context) error {
	regionKeys, err := w.discoverOrCreateKeys(ctx)
	if err != nil {
		return err
	}

	database := store.NewFileStore(*w.filename)

	// If the file exists, we'll make changes to its template rather than replace it.
	keyConfigs, err := database.Get(store.KeyTemplateName)
	if err != nil && !(err == store.ErrNameNotFound || errors.Is(err, fs.ErrNotExist)) {
		return err
	}

	// Convert keyConfigs into a map of KeyID -> Value so that we can replace any existing
	// entries for these keys. This allows the algorithm parameter to change w/o creating
	// duplicate entries, and leaves other entries alone.
	keyIDToValue := make(map[string]store.Value)
	for _, value := range keyConfigs {
		keyIDToValue[keymanager.KmsLabel+value.KeyID] = value
	}

	// Iterate over the discovered/created keys and set values for them in keyIDToValue.
	for _, keyArn := range regionKeys {
		keyIDToValue[keymanager.KmsLabel+keyArn] = store.Value{
			Key: store.Key{
				KeyID:      keyArn,
				KeyManager: keymanager.KmsLabel,
				Algorithm:  *w.algorithm,
			},
		}
	}

	// Turn keyIDToValue back into an array by converting the map values into a list.
	var updatedTemplate []store.Value
	for _, v := range keyIDToValue {
		updatedTemplate = append(updatedTemplate, v)
	}

	fmt.Printf("The template used by %s has been updated to include %s: %s.\n",
		*w.filename,
		stringsFunc.Pluralize("key", len(regionKeys)),
		stringStringMapValues(regionKeys))

	return database.Put(store.KeyTemplateName, updatedTemplate)
}

func collectRegionInfo(ctx context.Context, stackName, keyAlias string, regions []string) (map[string]string, []string, error) {
	regionErrors := make(map[string][]error)
	regionKeys := make(map[string]string)
	var regionsMissing []string

	fmt.Println("Still Running")
	for _, region := range regions {
		var keyExists, stackExists bool

		if exists, err := checkCloudFormationStackExists(ctx, stackName, region); err != nil {
			regionErrors[region] = append(regionErrors[region], err)
		} else {
			stackExists = exists
		}

		if regionKey, err := checkKmsKeyExists(ctx, keyAlias, region); err != nil {
			regionErrors[region] = append(regionErrors[region], err)
		} else if len(regionKey) > 0 {
			keyExists = true
			regionKeys[region] = regionKey
		} else {
			regionsMissing = append(regionsMissing, region)
		}

		if !keyExists && stackExists {
			regionErrors[region] = append(regionErrors[region],
				fmt.Errorf("A CloudFormation stack named '%s' exists, but the corresponding "+
					"key alias '%s' does not. The most likely cause of this is that a key "+
					"was incompletely deleted. You can resolve this by deleting the stack "+
					"or by using an alternate label. To delete the stack, run: aws --region %s "+
					"cloudformation delete-stack --stack-name %s. ", stackName, keyAlias, region,
					stackName))
		}
	}

	var err error
	for region, errorList := range regionErrors {
		for _, oneErr := range errorList {
			fmt.Fprintf(os.Stderr, "%s: %s\n", region, oneErr)
		}
		err = fmt.Errorf("Please manually resolve the issues and try again.")
	}

	return regionKeys, regionsMissing, err
}

func checkCloudFormationStackExists(ctx context.Context, stackName, region string) (bool, error) {
	cfg := myAWS.MustNewConfig(ctx, config.WithRegion(region))
	cfclient := cloudformation.NewFromConfig(cfg)
	_, err := cfclient.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "ValidationError" &&
				strings.Contains(apiErr.ErrorMessage(), "does not exist") {
				return false, nil
			}

		}
		return false, err
	}
	return true, nil
}

func checkKmsKeyExists(ctx context.Context, keyAlias, region string) (string, error) {
	cfg := myAWS.MustNewConfig(ctx, config.WithRegion(region))
	kmsClient := kms.NewFromConfig(cfg)
	p := kms.NewListAliasesPaginator(kmsClient, &kms.ListAliasesInput{})
	for p.HasMorePages() {
		output, err := p.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("could not list aliases: %w", err)
		}

		for _, aliasRecord := range output.Aliases {
			if *aliasRecord.AliasName != keyAlias {
				continue
			}
			keyDetails, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aliasRecord.TargetKeyId})
			if err != nil {
				return "", fmt.Errorf("described key faild: %w", err)
			}
			if !keyDetails.KeyMetadata.Enabled {
				return "", fmt.Errorf(
					"there is a KMS key in %s with a matching alias, but the key is "+
						"disabled. If the alias is no longer in use, "+
						"you may try again after deleting the alias. "+
						"To delete the alias, run: "+
						"aws --region "+
						"%s kms delete-alias --alias-name %s", region, region, keyAlias)
			}
			return *aliasRecord.AliasArn, nil
		}
	}
	return "", nil
}

func (w *kmsInit) discoverOrCreateKeys(ctx context.Context) (map[string]string, error) {
	fmt.Printf("Checking %s for the '%s' label.\n",
		stringsFunc.FriendlyJoin(*w.regions),
		*w.label)

	aliasName := kmsAliasName(*w.label)
	stackName := cfStackName(*w.label)

	existingAliases, regionsMissingKeys, err := collectRegionInfo(ctx, stackName, aliasName, *w.regions)
	if err != nil {
		return nil, err
	}
	if len(existingAliases) > 0 && len(regionsMissingKeys) > 0 && !*w.createMissingKeys {
		return nil, fmt.Errorf("You've requested to use %d regions, but %d regions already "+
			"have keys provisioned for "+
			"label '%s'. If you'd like the additional regions to be provisioned, re-run "+
			"this command with the --create-missing-keys flag. If you'd like to use a new set of keys, "+
			"re-run with the --label flag. If you'd like to choose a different set of regions, use"+
			"the --regions flag. Run 'biscuit kms init --help' for more information.",
			len(*w.regions),
			len(existingAliases),
			*w.label)
	}
	if len(existingAliases) > 0 {
		fmt.Printf("Found %d pre-existing keys.\n", len(existingAliases))
	}
	if len(existingAliases) == 0 || *w.createMissingKeys {
		finalAdminArns, finalUserArns, err := w.constructArns(ctx)
		if err != nil {
			return nil, err
		}

		fmt.Printf("%s %s need to be provisioned.\n", stringsFunc.Pluralize("Region", len(regionsMissingKeys)),
			stringsFunc.FriendlyJoin(regionsMissingKeys))

		errs := make(chan error, len(regionsMissingKeys))
		var wg sync.WaitGroup
		for _, region := range regionsMissingKeys {
			wg.Add(1)
			go func(region string) {
				defer wg.Done()
				started := time.Now()
				fmt.Printf("%s: Creating resources using CloudFormation. This may take a while.\n", region)
				existingAliases[region], err = w.createKeyInRegion(ctx, region, stackName,
					aliasName, finalAdminArns, finalUserArns)
				if err != nil {
					errs <- fmt.Errorf("%s: %s", region, err)
				}
				fmt.Fprintf(os.Stderr, "%s: finished in %s.\n", region, time.Since(started))
			}(region)
		}
		wg.Wait()
		close(errs)
		for err = range errs {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		if err != nil {
			return nil, err
		}
	}
	return existingAliases, nil
}

// createKeyInRegion creates a key for a region and returns the Alias's ARN.
func (w *kmsInit) createKeyInRegion(ctx context.Context, region, stackName, aliasName string, finalAdminArns, finalUserArns []string) (string, error) {
	specs := cloudformationStack{
		params: []types.Parameter{
			{ParameterKey: aws.String("AdministratorPrincipals"), ParameterValue: aws.String(strings.Join(finalAdminArns, ","))},
			{ParameterKey: aws.String("UserPrincipals"), ParameterValue: aws.String(strings.Join(finalUserArns, ","))},
			{ParameterKey: aws.String("KeyDescription"), ParameterValue: aws.String("Key used for securing secrets (" + *w.label + ").")},
			{ParameterKey: aws.String("CreateSimpleRoles"), ParameterValue: aws.String(truefalse(*w.createSimpleRoles))},
			{ParameterKey: aws.String("AllowIAMPoliciesToControlKeyAccess"), ParameterValue: aws.String(truefalse(!*w.disableIam))},
		},
		region:    region,
		stackName: stackName,
	}
	if len(*w.cloudformationTemplateURL) > 0 {
		specs.templateURL = w.cloudformationTemplateURL
	} else {
		specs.templateBody = &w.keyCloudformationTemplate
	}
	outputs, err := specs.createAndWait(ctx)
	if err != nil {
		return "", err
	}
	keyArn := outputs["KeyArn"]
	if keyArn == "" {
		return "", fmt.Errorf("Stack %s does not have an Output named KeyArn.", stackName)
	}

	aliasARN, err := createAlias(ctx, region, aliasName, keyArn)
	return aliasARN, err
}

func createAlias(ctx context.Context, region, aliasName, keyArn string) (string, error) {
	fmt.Printf("%s: creating alias '%s' for key %s.\n", region, aliasName, keyArn)
	cfg := myAWS.MustNewConfig(ctx, config.WithRegion(region))

	client := kmsHelper{kms.NewFromConfig(cfg)}
	if _, err := client.CreateAlias(ctx, &kms.CreateAliasInput{
		TargetKeyId: aws.String(keyArn),
		AliasName:   aws.String(aliasName)}); err != nil {
		return "", err
	}
	fmt.Printf("%s: fetching ARN for the new alias.\n", region)
	aliasListEntry, err := client.GetAliasByName(ctx, aliasName)
	if err != nil {
		return "", err
	}
	if aliasListEntry == nil {
		return "", errors.New("failed to discover ARN of new alias")
	}
	return *aliasListEntry.AliasArn, nil
}

func truefalse(iff bool) string {
	if iff {
		return "true"
	}
	return "false"
}

func (w *kmsInit) constructArns(ctx context.Context) ([]string, []string, error) {
	cfg := myAWS.MustNewConfig(ctx)
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	awsAccountID := *callerIdentity.Account
	fmt.Printf("Detected account ID #%s and that I am %s.\n", awsAccountID, *callerIdentity.Arn)
	adminArns := arn.CleanList(awsAccountID, *w.administratorArns+","+*callerIdentity.Arn)
	if len(adminArns) == 0 {
		return nil, nil, fmt.Errorf("there must be a least one administrator ARN")
	}

	userArns := arn.CleanList(awsAccountID, *w.userArns+","+*callerIdentity.Arn)
	if len(userArns) == 0 {
		return nil, nil, fmt.Errorf("there must be a least one user ARN")

	}
	fmt.Printf("Administrative actions will be allowed by %s\n", adminArns)
	fmt.Printf("User actions will be allowed by %s\n", userArns)
	return adminArns, userArns, nil
}

func stringStringMapValues(input map[string]string) []string {
	results := []string{}
	for _, value := range input {
		results = append(results, value)
	}
	sort.Strings(results)
	return results
}
