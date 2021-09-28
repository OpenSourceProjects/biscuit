package biscuit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"sync"

	"github.com/dcoker/biscuit/algorithms"
	"github.com/dcoker/biscuit/algorithms/secretbox"
	"github.com/dcoker/biscuit/cmd/internal/shared"
	"github.com/dcoker/biscuit/keymanager"
	"github.com/dcoker/biscuit/store"
	"github.com/spf13/cobra"
	"gopkg.in/alecthomas/kingpin.v2"
)

func putCmd(ctx context.Context) *cobra.Command {
	var filename string
	var keyID string
	var keyManager string
	var algo string
	var fromFileStr string
	cmd := &cobra.Command{
		Use:     "put <key> [value]",
		Aliases: []string{"write"},
		Short:   "Write a secret",
		Args:    cobra.RangeArgs(1, 2),
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
			var value string
			var fromFile *os.File = nil
			var err error
			if len(args) > 1 {
				value = args[1]
			}

			if fromFileStr != "" {
				fromFile, err = os.Open(fromFileStr)
				if err != nil {
					return fmt.Errorf("could not open file: %w", err)
				}
				defer fromFile.Close()
			}

			p := &put{
				keyID:      &keyID,
				keyManager: &keyManager,
				name:       &name,
				algo:       &algo,
				filename:   &filename,
				value:      &value,
				fromFile:   &fromFile,
			}
			return p.Run(ctx)
		},
	}
	cmd.Flags().StringVarP(&filename, "filename", "f", "", "Name of file storing the secrets. If the environment variable BISCUIT_FILENAME")

	cmd.Flags().StringVarP(&keyID, "key-id", "k", "",
		"The ID of the key to use. This can be a full key ARN, or just the alias/ or the key ID (if "+
			"AWS_REGION is set). If --key-id is not set, the "+store.KeyTemplateName+" "+
			"entry from FILE will be used "+
			"(if present).")
	cmd.Flags().StringVarP(&keyManager, "key-manager", "p", keymanager.GetDefaultKeyManager(),
		"Source of envelope encryption keys. Options: "+
			strings.Join(keymanager.GetKeyManagers(), ", "),
	)

	cmd.Flags().StringVarP(&fromFileStr, "from-file", "i", "", "Read the secret from file instead of the command line")

	cmd.Flags().StringVarP(&algo, "algorithm", "a", secretbox.Name,
		"Encryption algorithm. If the environment variable BISCUIT_ALGORITHM is "+
			"set, it will be used as the default value. Options: "+
			strings.Join(algorithms.GetRegisteredAlgorithmsNames(), ", "),
	)
	return cmd
}

// Put implements the "put" command.
type put struct {
	keyID      *string
	keyManager *string
	name       *string
	fromFile   **os.File
	value      *string
	algo       *string
	filename   *string
}

var (
	errFileDoesNotExist = errors.New("The file you've specified does not exist. Please create a file with " +
		"kms init or specify --key-id.")
	errConflictingValue = errors.New(
		"Please specify either a secret in a positional argument, or use --from-file, " +
			"but not both.")
)

// NewPut configures the command for storing secrets.
func NewPut(c *kingpin.CmdClause) shared.Command {
	write := &put{}
	write.keyID = c.Flag("key-id",
		"The ID of the key to use. This can be a full key ARN, or just the alias/ or the key ID (if "+
			"AWS_REGION is set). If --key-id is not set, the "+store.KeyTemplateName+" "+
			"entry from FILE will be used "+
			"(if present).").Short('k').String()
	write.keyManager = c.Flag("key-manager", "Source of envelope encryption keys. Options: "+
		strings.Join(keymanager.GetKeyManagers(), ", ")).
		Default(keymanager.GetDefaultKeyManager()).Short('p').Enum(keymanager.GetKeyManagers()...)
	write.name = c.Arg("name", "Name of the secret.").Required().String()
	write.value = c.Arg("secret", "Value of the secret.").String()
	write.fromFile = c.Flag("from-file", "Read the secret from FILE instead "+
		"of the command line.").PlaceHolder("FILE").Short('i').File()
	write.algo = shared.AlgorithmFlag(c)
	write.filename = shared.FilenameFlag(c)

	return write
}

type encryptResult struct {
	value store.Value
	err   error
}

// Run runs the command.
func (w *put) Run(ctx context.Context) error {
	database := store.NewFileStore(*w.filename)

	keys, err := w.chooseKeys(database)
	if err != nil {
		return err
	}

	plaintext, err := w.choosePlaintext()
	if err != nil {
		return err
	}

	results := make(chan encryptResult, len(keys))
	var wg sync.WaitGroup
	for _, keyConfig := range keys {
		wg.Add(1)
		go func(keyConfig store.Key, plaintext []byte) {
			defer wg.Done()
			value, err := encryptOne(ctx, keyConfig, *w.name, plaintext)
			results <- encryptResult{value, err}
		}(keyConfig, plaintext)
	}
	wg.Wait()
	close(results)

	var valueList []store.Value
	for value := range results {
		if value.err != nil {
			return value.err
		}
		valueList = append(valueList, value.value)
	}

	// If the file doesn't have a template, create one from the keys used here.
	if _, err := database.Get(store.KeyTemplateName); errors.Is(err, fs.ErrNotExist) {
		var values []store.Value
		for _, key := range keys {
			values = append(values, store.Value{Key: key})
		}
		err := database.Put(store.KeyTemplateName, values)
		if err != nil {
			return err
		}
	}

	return database.Put(*w.name, valueList)
}

func (w *put) chooseKeys(database store.FileStore) ([]store.Key, error) {
	if len(*w.keyID) > 0 {
		var keys []store.Key
		split := strings.Split(*w.keyID, ",")
		for _, key := range split {
			keys = append(keys, store.Key{
				KeyManager: *w.keyManager,
				KeyID:      key,
				Algorithm:  *w.algo})
		}
		return keys, nil
	}
	algo, err := algorithms.Get(*w.algo)
	if err != nil {
		return nil, err
	}
	if !algo.NeedsKey() {
		return []store.Key{{Algorithm: *w.algo}}, nil
	}
	templateKeys, err := database.GetKeyIds()
	if os.IsNotExist(err) {
		return nil, errFileDoesNotExist
	}
	if err != nil {
		return nil, err
	}
	return templateKeys, nil
}

func (w *put) choosePlaintext() ([]byte, error) {
	if *w.fromFile != nil && len(*w.value) > 0 {
		return nil, errConflictingValue
	}
	if *w.fromFile != nil {
		plaintext, err := io.ReadAll(*w.fromFile)
		return plaintext, err
	}
	return []byte(*w.value), nil
}

func encryptOne(ctx context.Context, keyConfig store.Key, name string, plaintext []byte) (store.Value, error) {
	var value store.Value
	algo, err := algorithms.Get(keyConfig.Algorithm)
	if err != nil {
		return value, err
	}
	value.Algorithm = keyConfig.Algorithm

	var envelopeKey keymanager.EnvelopeKey
	if algo.NeedsKey() {
		keyManager, err := keymanager.New(keyConfig.KeyManager)
		if err != nil {
			return value, err
		}
		value.KeyManager = keyManager.Label()
		envelopeKey, err = keyManager.GenerateEnvelopeKey(ctx, keyConfig.KeyID, name)
		if err != nil {
			return value, err
		}
		value.KeyID = envelopeKey.ResolvedID
		value.KeyCiphertext = base64.StdEncoding.EncodeToString(envelopeKey.Ciphertext)
	}

	ciphertext, err := algo.Encrypt(envelopeKey.Plaintext, plaintext)
	if err != nil {
		return value, err
	}
	value.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	return value, nil
}
