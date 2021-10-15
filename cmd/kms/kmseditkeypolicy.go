package kms

import (
	"context"
	"fmt"

	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/dcoker/biscuit/cmd/internal/assets"
	"github.com/dcoker/biscuit/cmd/internal/flags"
	"github.com/spf13/cobra"
)

func editKeyPolicyCmd() *cobra.Command {
	regions := flags.CSV([]string{"us-east-1", "us-west-1", "us-west-2"})
	label := flags.NewRegex("^[a-zA-Z0-9_-]+$", "default")
	var forceRegion string
	cmd := &cobra.Command{
		Use:   "edit-key-policy",
		Short: "Edit the KMS Key Policy for a label across regions",
		Long:  assets.Must("data/kmseditkeypolicy.txt"),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			rs := []string(regions)
			l := label.String()
			edit := &kmsEditKeyPolicy{
				regions:     &rs,
				label:       &l,
				forceRegion: &forceRegion,
			}
			return edit.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&forceRegion, "force-region", "",
		"If set, the key policies will not be checked for consistency between regions and "+
			"the editor will open with the policy from the specified region")
	cmd.Flags().VarP(&regions, "regions", "r", "Comma-delimited list of regions to provision keys in. If the enviroment variable BISCUIT_REGIONS "+
		"is set, it will be used as the default value.")
	cmd.Flags().VarP(label, "label", "l",
		"Label for the keys created. This is used to uniquely identify the keys across regions. There can "+
			"be multiple labels in use within an AWS account. If the environment variable BISCUIT_LABEL "+
			"is set, it will be used as the default value")
	return cmd
}

var (
	errNoEditorFound        = errors.New("Set your editor preference with VISUAL or EDITOR environment variables.")
	errNewPolicyIsZeroBytes = errors.New("No change: the new policy is empty.")
	errFileUnchanged        = errors.New("No change: the new policy is the same as the existing policy.")
)

type kmsEditKeyPolicy struct {
	label       *string
	regions     *[]string
	forceRegion *string
}

// Run the command.
func (r *kmsEditKeyPolicy) Run(ctx context.Context) error {
	aliasName := kmsAliasName(*r.label)
	mrk, err := NewMultiRegionKey(ctx, aliasName, *r.regions, *r.forceRegion)
	if err != nil {
		return err
	}

	mrk.Policy, err = prettifyJSON(mrk.Policy)
	if err != nil {
		return err
	}

	newPolicy, err := launchEditor(mrk.Policy)
	if err != nil {
		return err
	}
	indentedPolicy, err := prettifyJSON(newPolicy)
	if err != nil {
		return err
	}

	if err := mrk.SetKeyPolicy(ctx, indentedPolicy); err != nil {
		return err
	}
	fmt.Printf("New policy saved.\n")
	return nil
}

func launchEditor(contents string) (string, error) {
	f, err := os.CreateTemp("", "secrets")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(contents); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	editor, err := findEditor()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(editor, f.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	bytes, err := os.ReadFile(f.Name())
	if err != nil {
		return "", err
	}
	newContents := strings.TrimSpace(string(bytes))
	if len(newContents) == 0 {
		return "", errNewPolicyIsZeroBytes
	}
	if newContents == strings.TrimSpace(contents) {
		return "", errFileUnchanged
	}
	return newContents, nil
}

func findEditor() (string, error) {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		candidate := os.Getenv(name)
		if len(candidate) > 0 {
			return candidate, nil
		}
	}
	return "", errNoEditorFound
}

func prettifyJSON(content string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(content), &v); err != nil {
		return "", err
	}
	indentedPolicyBytes, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return "", err
	}
	indentedPolicy := string(indentedPolicyBytes)
	return indentedPolicy, nil
}
