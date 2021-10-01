package kms

import (
	"fmt"
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
