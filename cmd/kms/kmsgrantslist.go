package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/dcoker/biscuit/cmd/internal/assets"
	"github.com/dcoker/biscuit/internal/yaml"
	"github.com/dcoker/biscuit/keymanager"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
)

func grantListCmd() *cobra.Command {
	long := assets.Must("data/kmsgrantslist.txt")
	var filename string
	cmd := &cobra.Command{
		Use:   "list <name>",
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
			ctx := cmd.Context()
			name := args[0]
			list := &kmsGrantsList{
				name:     &name,
				filename: &filename,
			}
			cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")
			return list.Run(ctx)
		},
	}
	return cmd

}

type kmsGrantsList struct {
	name, filename *string
}

type grantsForOneAlias struct {
	GranteePrincipal        *string
	RetiringPrincipal       *string                `yaml:",omitempty"`
	EncryptionContextSubset map[string]string      `yaml:",flow,omitempty"`
	Operations              []types.GrantOperation `yaml:",flow"`
	GrantIds                map[string]string
}

// Run runs the command.
func (w *kmsGrantsList) Run(ctx context.Context) error {
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

	output := make(map[string]map[string]grantsForOneAlias)
	for aliasName, regions := range aliases {
		mrk, err := NewMultiRegionKey(ctx, aliasName, regions, "")
		if err != nil {
			return err
		}
		regionGrants, err := mrk.GetGrantDetails(ctx)
		if err != nil {
			return err
		}

		// Group by grant name and collect grant IDs into a list by region.
		n2e := make(map[string]grantsForOneAlias)
		for region, grants := range regionGrants {
			for _, grant := range grants {
				if entry, present := n2e[*grant.Name]; present {
					entry.GrantIds[region] = *grant.GrantId
				} else {
					entry := grantsForOneAlias{
						GranteePrincipal:  grant.GranteePrincipal,
						RetiringPrincipal: grant.RetiringPrincipal,
						Operations:        grant.Operations,
					}
					if grant.Constraints != nil {
						entry.EncryptionContextSubset = grant.Constraints.EncryptionContextSubset
					}
					entry.GrantIds = make(map[string]string)
					entry.GrantIds[region] = *grant.GrantId
					n2e[*grant.Name] = entry
				}
			}
		}
		if len(n2e) > 0 {
			output[aliasName] = n2e
		}
	}
	if len(output) > 0 {
		fmt.Print(yaml.ToString(output))
	}
	return nil
}
