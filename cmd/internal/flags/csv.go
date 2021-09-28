package flags

import "strings"

type CSV []string

func (a CSV) String() string {
	return strings.Join(a, ",")
}

func (a *CSV) Set(p string) error {
	*a = strings.Split(p, ",")
	return nil
}
func (a *CSV) Type() string {
	return "string"
}
