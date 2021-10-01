package kms

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

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
	)
	return cmd
}
