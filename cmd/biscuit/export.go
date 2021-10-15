package biscuit

import (
	"errors"
	"fmt"
	"os"

	"github.com/dcoker/biscuit/cmd/internal/flags"
	"github.com/dcoker/biscuit/internal/yaml"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
)

func exportCmd() *cobra.Command {
	var filename string
	awsPriorities := flags.CSV([]string{os.Getenv("AWS_REGION")})
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print all secrets to stdout in plaintext YAML",
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
			database := store.NewFileStore(filename)
			entries, err := database.GetAll()
			if err != nil {
				return err
			}
			errs := 0
			for name, values := range entries {
				if name == store.KeyTemplateName {
					continue
				}

				store.SortByKmsRegion(awsPriorities)(values)
				for _, v := range values {
					bytes, err := decryptOneValue(ctx, v, name)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: unable to decrypt, skipping: %s\n", err)
						errs++
						continue
					}
					fmt.Print(yaml.ToString(map[string]string{name: string(bytes)}))
					break
				}
			}
			if errs > 0 {
				return errors.New("there were errors exporting")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")
	cmd.Flags().VarP(&awsPriorities, "aws-region-priority", "p", awsPriorityTxt)
	return cmd
}
