package kms

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

const (
	// ProgName is the name of this program.
	ProgName = "biscuit"

	// AliasPrefix is the prefix of all KMS Key Aliases.
	AliasPrefix = "alias/" + ProgName + "-"

	// GrantPrefix is the prefix of all KMS Grant Names.
	GrantPrefix = ProgName + "-"
)

func kmsAliasName(label string) string {
	return AliasPrefix + label
}

func cfStackName(label string) string {
	return fmt.Sprintf("%s-%s", ProgName, label)
}

type regionError struct {
	Region string
	Err    error
}

func (r regionError) Error() string {
	return fmt.Sprintf("%s: %s", r.Region, r.Err)
}

func Cmd(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use: "kms",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("must select a subcommand of 'kms'")
		},
	}
	cmd.AddCommand(
		initCmd(ctx),
		getCallerIDCmd(ctx),
		deprovisionCmd(ctx),
		editKeyPolicyCmd(ctx),
		grantCmd(ctx),
	)
	return cmd
}

func grantCmd(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grants",
		Short: "Mange KMS grants",
	}
	cmd.AddCommand(
		grantCreateCmd(ctx),
		grantListCmd(ctx),
		grantsRetireCmd(ctx),
	)
	return cmd

}
