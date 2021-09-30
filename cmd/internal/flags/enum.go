package flags

import (
	"fmt"
	"strings"
)

type enum struct {
	Allowed []string
	Value   string
}

func NewEnum(allowed []string, d string) *enum {
	return &enum{
		Allowed: allowed,
		Value:   d,
	}
}

func (a enum) String() string {
	return a.Value
}

func (a *enum) Set(p string) error {
	if !isIncluded(a.Allowed, p) {
		return fmt.Errorf("%s is not included in %s", p, strings.Join(a.Allowed, "|"))
	}
	a.Value = p
	return nil
}

func (a *enum) Type() string {
	return "string"
}

func isIncluded(opts []string, val string) bool {
	for _, opt := range opts {
		if val == opt {
			return true
		}
	}
	return false
}
