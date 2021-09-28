package biscuit

import (
	"context"
	"fmt"

	"github.com/dcoker/biscuit/cmd/internal/shared"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
	"gopkg.in/alecthomas/kingpin.v2"
)

func listCmd(ctx context.Context) *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets",
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

			database := store.NewFileStore(filename)

			entries, err := database.GetAll()
			if err != nil {
				return err
			}
			for name := range entries {
				if name == store.KeyTemplateName {
					continue
				}
				fmt.Printf("%s\n", name)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")
	return cmd
}

type list struct {
	filename *string
}

// NewList configures the command to list secrets.
func NewList(c *kingpin.CmdClause) shared.Command {
	return &list{filename: shared.FilenameFlag(c)}
}

// Run runs the command.
func (r *list) Run(ctx context.Context) error {
	database := store.NewFileStore(*r.filename)

	entries, err := database.GetAll()
	if err != nil {
		return err
	}
	for name := range entries {
		if name == store.KeyTemplateName {
			continue
		}
		fmt.Printf("%s\n", name)
	}
	return nil
}
