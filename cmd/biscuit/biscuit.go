package biscuit

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/dcoker/biscuit/algorithms"
	"github.com/dcoker/biscuit/algorithms/aesgcm256"
	"github.com/dcoker/biscuit/algorithms/plain"
	"github.com/dcoker/biscuit/algorithms/secretbox"
	"github.com/dcoker/biscuit/cmd/internal/shared"
	"github.com/dcoker/biscuit/cmd/kms"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	Version = "n/a"
)

//go:embed data/*
var fileSystem embed.FS

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

func Cmd(ctx context.Context) *cobra.Command {
	if err := registerAlgorithms(); err != nil {
		panic(err)
	}
	cmd := &cobra.Command{
		Use:   "biscuit",
		Short: "Manage KMS secrets in source code",
		Long:  mustAsset("data/usage.txt"),
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
		getCmd(ctx),
		putCmd(ctx),
		listCmd(ctx),
		exportCmd(ctx),
		kms.Cmd(ctx),
	)
	return cmd
}

func Command(ctx context.Context) error {
	var once sync.Once

	var err error
	once.Do(func() {
		err = registerAlgorithms()
	})
	if err != nil {
		return err
	}

	app := kingpin.New(shared.ProgName, mustAsset("data/usage.txt"))
	app.Version(Version)
	app.UsageTemplate(kingpin.LongHelpTemplate)
	getFlags := app.Command("get", "Read a secret.")
	putFlags := app.Command("put", "Write a secret.")
	listFlags := app.Command("list", "List secrets.")
	exportFlags := app.Command("export", "Print all secrets to stdout in plaintext YAML.")
	kmsFlags := app.Command("kms", "AWS KMS-specific operations.")
	kmsIDFlags := kmsFlags.Command("get-caller-identity", "Print the AWS credentials.")
	kmsInitFlags := kmsFlags.Command("init", mustAsset("data/kmsinit.txt"))
	kmsDeprovisionFlags := kmsFlags.Command("deprovision", "Deprovision AWS resources.")
	kmsEditKeyPolicyFlags := kmsFlags.Command("edit-key-policy", mustAsset("data/kmseditkeypolicy.txt"))
	kmsGrantsFlags := kmsFlags.Command("grants", "Manage KMS grants.")
	kmsGrantsListFlags := kmsGrantsFlags.Command("list", mustAsset("data/kmsgrantslist.txt"))
	kmsGrantsCreateFlags := kmsGrantsFlags.Command("create", mustAsset("data/kmsgrantcreate.txt"))
	kmsGrantsRetireFlags := kmsGrantsFlags.Command("retire", mustAsset("data/kmsgrantsretire.txt"))

	getCommand := NewGet(getFlags)
	writeCommand := NewPut(putFlags)
	listCommand := NewList(listFlags)
	exportCommand := NewExport(exportFlags)
	kmsIDCommand := kms.KmsGetCallerIdentity{}
	kmsEditKeyPolicy := kms.NewKmsEditKeyPolicy(kmsEditKeyPolicyFlags)
	kmsGrantsListCommand := kms.NewKmsGrantsList(kmsGrantsListFlags)
	kmsGrantsCreateCommand := kms.NewKmsGrantsCreate(kmsGrantsCreateFlags)
	kmsGrantsRetireCommand := kms.NewKmsGrantsRetire(kmsGrantsRetireFlags)
	kmsInitCommand := kms.NewKmsInit(kmsInitFlags, mustAsset("data/awskms-key.template"))
	kmsDeprovisionCommand := kms.NewKmsDeprovision(kmsDeprovisionFlags)

	behavior := kingpin.MustParse(app.Parse(os.Args[1:]))
	switch behavior {
	case getFlags.FullCommand():
		return getCommand.Run(ctx)
	case putFlags.FullCommand():
		return writeCommand.Run(ctx)
	case listFlags.FullCommand():
		return listCommand.Run(ctx)
	case kmsIDFlags.FullCommand():
		return kmsIDCommand.Run(ctx)
	case kmsInitFlags.FullCommand():
		return kmsInitCommand.Run(ctx)
	case kmsEditKeyPolicyFlags.FullCommand():
		return kmsEditKeyPolicy.Run(ctx)
	case kmsGrantsCreateFlags.FullCommand():
		return kmsGrantsCreateCommand.Run(ctx)
	case kmsGrantsListFlags.FullCommand():
		return kmsGrantsListCommand.Run(ctx)
	case kmsDeprovisionFlags.FullCommand():
		return kmsDeprovisionCommand.Run(ctx)
	case kmsGrantsRetireFlags.FullCommand():
		return kmsGrantsRetireCommand.Run(ctx)
	case exportFlags.FullCommand():
		return exportCommand.Run(ctx)
	default:
		return fmt.Errorf("not implemented")
	}
}

func mustAsset(filename string) string {
	bytes, err := fileSystem.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
