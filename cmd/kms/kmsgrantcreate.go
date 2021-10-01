package kms

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/dcoker/biscuit/cmd/internal/assets"
	myAWS "github.com/dcoker/biscuit/internal/aws"
	"github.com/dcoker/biscuit/internal/aws/arn"
	"github.com/dcoker/biscuit/internal/yaml"
	"github.com/dcoker/biscuit/keymanager"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
)

type enumGrants struct {
	Allowed []types.GrantOperation
	Value   []types.GrantOperation
}

func newEnumGrants(d []types.GrantOperation) *enumGrants {
	var g types.GrantOperation
	return &enumGrants{
		Allowed: g.Values(),
		Value:   d,
	}
}

func (a enumGrants) String() string {
	return strings.Join(mapToStr(a.Value), ",")
}

func mapToStr(grants []types.GrantOperation) []string {
	val := []string{}
	for _, g := range grants {
		val = append(val, string(g))
	}
	return val
}

func mapFromString(grants []string) []types.GrantOperation {
	val := []types.GrantOperation{}
	for _, g := range grants {
		val = append(val, types.GrantOperation(g))
	}
	return val
}

func (a *enumGrants) Set(p string) error {
	grantStrs := strings.Split(p, ",")
	grants := mapFromString(grantStrs)
	isIncluded := func(grants []types.GrantOperation, g types.GrantOperation) bool {
		for _, grant := range grants {
			if g == grant {
				return true
			}
		}
		return false
	}
	for _, g := range grants {
		if !isIncluded(g.Values(), g) {
			return fmt.Errorf("%s is not included in %s", p, strings.Join(mapToStr(g.Values()), "|"))
		}
	}

	a.Value = grants
	return nil
}

func (a *enumGrants) Type() string {
	return "string"
}

func grantCreateCmd(ctx context.Context) *cobra.Command {
	var retiringPrincipal string
	var granteePrincipal string
	var filename string
	long := assets.Must("data/kmsgrantcreate.txt")
	grants := newEnumGrants([]types.GrantOperation{
		types.GrantOperationDecrypt,
		types.GrantOperationRetireGrant,
	})
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: strings.Split(long, "\n")[0],
		Long:  long,
		Args:  cobra.ExactArgs(1),
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
			name := args[0]
			allNames, err := cmd.Flags().GetBool("all-names")
			if err != nil {
				return err
			}
			create := &kmsGrantsCreate{
				name:              &name,
				granteePrincipal:  &granteePrincipal,
				retiringPrincipal: &retiringPrincipal,
				filename:          &filename,
				operations:        grants.Value,
				allNames:          &allNames,
			}
			return create.Run(ctx)
		},
	}
	cmd.Flags().Bool("all-names", false, "If set, the grant allows the grantee to decrypt any values encrypted under "+
		"the keys that the named secret is encrypted with.")
	cmd.Flags().StringVarP(&retiringPrincipal, "retiring-principal", "e", "", "The ARN that can retire the grant")
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")
	var g types.GrantOperation
	cmd.Flags().VarP(grants, "operations", "o",
		"Comma-separated list of AWS KMS operations this grant is allowing. Options: "+
			strings.Join(mapToStr(g.Values()), ","),
	)
	return cmd
}

type kmsGrantsCreate struct {
	name,
	granteePrincipal,
	retiringPrincipal,
	filename *string
	operations []types.GrantOperation
	allNames   *bool
}

type grantsCreatedOutput struct {
	Name string
	// Alias -> Region -> Grant
	Aliases map[string]map[string]grantDetails
}

type grantDetails struct {
	GrantID,
	GrantToken string
}

// Run runs the command.
func (w *kmsGrantsCreate) Run(ctx context.Context) error {
	database := store.NewFileStore(*w.filename)
	values, err := database.Get(*w.name)
	if err != nil {
		return err
	}
	values = values.FilterByKeyManager(keymanager.KmsLabel)

	aliases, err := resolveValuesToAliasesAndRegions(ctx, values)
	if err != nil {
		return err
	}

	granteeArn, retireeArn, err := resolveGranteeArns(ctx, *w.granteePrincipal, *w.retiringPrincipal)
	if err != nil {
		return err
	}

	// The template from which grants in each region are created.
	createGrantInput := kms.CreateGrantInput{
		Operations:       w.operations,
		GranteePrincipal: &granteeArn,
	}
	if !*w.allNames {
		createGrantInput.Constraints = &types.GrantConstraints{
			EncryptionContextSubset: map[string]string{"SecretName": *w.name},
		}
	}
	if len(retireeArn) > 0 {
		createGrantInput.RetiringPrincipal = &retireeArn
	}

	grantName, err := computeGrantName(ctx, createGrantInput)
	if err != nil {
		return err
	}
	createGrantInput.Name = aws.String(grantName)

	output := grantsCreatedOutput{
		Name:    grantName,
		Aliases: make(map[string]map[string]grantDetails),
	}
	for alias, regionList := range aliases {
		mrk, err := NewMultiRegionKey(ctx, alias, regionList, "")
		if err != nil {
			return err
		}
		results, err := mrk.AddGrant(ctx, createGrantInput)
		if err != nil {
			return err
		}
		regionToGrantDetails := make(map[string]grantDetails)
		for region, grant := range results {
			regionToGrantDetails[region] = grantDetails{
				GrantID:    *grant.GrantId,
				GrantToken: *grant.GrantToken}
		}
		output.Aliases[alias] = regionToGrantDetails
	}
	fmt.Print(yaml.ToString(output))
	return nil
}

func computeGrantName(ctx context.Context, input kms.CreateGrantInput) (string, error) {
	cfg := myAWS.MustNewConfig(ctx)
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, nil)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	gob.Register(kms.CreateGrantInput{})
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode([]interface{}{input, callerIdentity.Arn}); err != nil {
		panic(err)
	}
	hashed := sha1.Sum(buf.Bytes())
	return grantPrefix + hex.EncodeToString(hashed[:])[:10], nil
}

func resolveValuesToAliasesAndRegions(ctx context.Context, values store.ValueList) (map[string][]string, error) {
	// The KeyID field may refer to a key/ or alias/ ARN. We need to resolve the alias for any key/ ARN
	// so that we can act on them across multiple regions. This loop resolves key/ ARNs into their appropriate
	// aliases, and maintains a list of regions for each alias.
	aliases := make(map[string][]string)
	for _, v := range values {
		arn, err := arn.New(v.KeyID)
		if err != nil {
			return nil, err
		}
		if arn.IsKmsAlias() {
			aliases["alias/"+arn.Resource] = append(aliases["alias/"+arn.Resource], arn.Region)
		} else if arn.IsKmsKey() {
			cfg := myAWS.MustNewConfig(ctx, config.WithRegion(arn.Region))
			client := kmsHelper{kms.NewFromConfig(cfg)}
			alias, err := client.GetAliasByKeyID(ctx, arn.Resource)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: Unable to find an alias for this key: %s\n", v.KeyID, err)
				return nil, err
			}
			aliases[alias] = append(aliases[alias], arn.Region)
		} else {
			return nil, err
		}
	}
	return aliases, nil
}

func resolveGranteeArns(ctx context.Context, granteePrincipal, retiringPrincipal string) (string, string, error) {
	cfg := myAWS.MustNewConfig(ctx)
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, nil)
	if err != nil {
		return "", "", err
	}
	granteeArn := arn.Clean(*callerIdentity.Account, granteePrincipal)
	if len(granteeArn) == 0 {
		return "", "", errors.New("grantee ARN must not be empty string")
	}
	retireeArn := arn.Clean(*callerIdentity.Account, retiringPrincipal)
	return granteeArn, retireeArn, nil
}
