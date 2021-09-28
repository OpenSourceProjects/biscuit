//go:generate go run cmd/support/generate/main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/smithy-go"
	"github.com/dcoker/biscuit/cmd/biscuit"
)

var (
	Version = "n/a"
)

func main() {
	os.Setenv("COLUMNS", "80") // hack to make --help output readable
	if err := biscuit.Command(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "MissingRegion":
				fmt.Fprintf(os.Stderr, "Hint: Check or set the AWS_REGION environment variable.\n")
			case "ExpiredTokenException":
				fmt.Fprintf(os.Stderr, "Hint: Refresh your credentials.\n")
			case "InvalidCiphertextException":
				fmt.Fprintf(os.Stderr, "Hint: key_ciphertext may be corrupted.\n")
			}
		}

		os.Exit(1)
	}
}
