package flags

import (
	"fmt"
	"regexp"
)

type regex struct {
	Pattern string
	Value   string
}

// NewRegex will create a new regular expression flag
//
// Pattern is first, default value is last
func NewRegex(r string, d string) *regex {
	return &regex{
		Pattern: r,
		Value:   d,
	}
}

func (a regex) String() string {
	return a.Value
}

func (a *regex) Set(p string) error {
	matched, err := regexp.MatchString(a.Pattern, p)
	if err != nil {
		return fmt.Errorf("%s does not match the regex %s: %w", p, a.Pattern, err)
	}
	if !matched {
		return fmt.Errorf("%s does not match %s", p, a.Pattern)
	}
	a.Value = p
	return nil
}
func (a *regex) Type() string {
	return "string"
}
