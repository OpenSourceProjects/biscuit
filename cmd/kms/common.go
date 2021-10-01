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

type errAliasNotFound struct {
	aliasName string
}

func (e *errAliasNotFound) Error() string {
	return fmt.Sprintf("key alias '%s' not found", e.aliasName)
}

type errNoAliasFoundForKey struct {
	keyID string
}

func (e *errNoAliasFoundForKey) Error() string {
	return fmt.Sprintf("no alias found for key %s", e.keyID)
}

type errPolicyMismatch struct {
	leftRegion, rightRegion string
}

func (e *errPolicyMismatch) Error() string {
	return fmt.Sprintf("the policies in region %s and %s do not match.", e.leftRegion, e.rightRegion)
}

type regionError struct {
	Region string
	Err    error
}

func (r regionError) Error() string {
	return fmt.Sprintf("%s: %s", r.Region, r.Err)
}

type regionErrorCollector chan regionError

func (r *regionErrorCollector) Coalesce() error {
	for err := range *r {
		if err.Err != nil {
			return &err
		}
	}
	return nil
}
