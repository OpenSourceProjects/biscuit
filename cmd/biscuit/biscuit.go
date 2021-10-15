package biscuit

import (
	"fmt"
	"strings"

	"github.com/dcoker/biscuit/algorithms"
	"github.com/dcoker/biscuit/algorithms/aesgcm256"
	"github.com/dcoker/biscuit/algorithms/plain"
	"github.com/dcoker/biscuit/algorithms/secretbox"
	"github.com/dcoker/biscuit/cmd/internal/assets"
	"github.com/dcoker/biscuit/cmd/kms"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	Version = "n/a"
)

const awsPriorityTxt = "comma-delimited list of AWS regions to prefer for " +
	"decryption operations. Biscuit will attempt to use the " +
	"KMS endpoints in these regions before trying the " +
	"other regions. If the environment variable AWS_REGION " +
	"is set, it will be used as the default value."

func registerAlgorithms() error {
	if err := algorithms.Register(secretbox.Name, secretbox.New()); err != nil {
		return err
	}
	if err := algorithms.Register(plain.Name, plain.New()); err != nil {
		return err
	}
	if err := algorithms.Register(aesgcm256.Name, aesgcm256.New()); err != nil {
		return err
	}
	return nil
}

const envPrefix = "BISCUIT"

func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()
	rp := strings.NewReplacer("-", "_", ".", "_")
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(rp)

	v.AutomaticEnv()

	if err := bindFlags(cmd, v); err != nil {
		return err
	}

	return nil
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) error {
	var errr error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			if err := v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)); err != nil {
				errr = err
				return
			}
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				errr = err
				return

			}
		}
	})
	return errr
}

func Cmd() *cobra.Command {
	if err := registerAlgorithms(); err != nil {
		panic(err)
	}
	cmd := &cobra.Command{
		Use:   "biscuit",
		Short: "Manage KMS secrets in source code",
		Long:  assets.Must("data/usage.txt"),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := initializeConfig(cmd); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not valid command")
		},
	}
	cmd.AddCommand(
		getCmd(),
		putCmd(),
		listCmd(),
		exportCmd(),
		kms.Cmd(),
	)
	return cmd
}
