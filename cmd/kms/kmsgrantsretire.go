package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/dcoker/biscuit/cmd/internal/assets"
	"github.com/dcoker/biscuit/keymanager"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
)

func grantsRetireCmd(ctx context.Context) *cobra.Command {
	long := assets.Must("data/kmsgrantsretire.txt")
	var filename string
	var grantName string

	cmd := &cobra.Command{
		Use:   "retire <name>",
		Short: strings.Split(long, "\n")[0],
		Long:  long,
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for k, v := range map[string]string{
				"filename":   filename,
				"grant-name": grantName,
			} {
				if v == "" {
					return fmt.Errorf("flag %s marked as required", k)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			retire := &kmsGrantsRetire{
				name:      &name,
				filename:  &filename,
				grantName: &grantName,
			}

			return retire.Run(ctx)
		},
	}
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")
	cmd.Flags().StringVar(&grantName, "grant-name", "", "The ID of the Grant to revoke")
	return cmd
}

type kmsGrantsRetire struct {
	filename, name, grantName *string
}

func (w *kmsGrantsRetire) Run(ctx context.Context) error {
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

	for aliasName, regions := range aliases {
		mrk, err := NewMultiRegionKey(ctx, aliasName, regions, "")
		if err != nil {
			return err
		}

		if err := mrk.RetireGrant(ctx, *w.grantName); err != nil {
			return err
		}
	}
	return nil
}
