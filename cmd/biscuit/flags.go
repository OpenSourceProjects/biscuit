package biscuit

import "strings"

type csvFlag []string

const awsPriorityTxt = "comma-delimited list of AWS regions to prefer for " +
	"decryption operations. Biscuit will attempt to use the " +
	"KMS endpoints in these regions before trying the " +
	"other regions. If the environment variable AWS_REGION " +
	"is set, it will be used as the default value."

func (a csvFlag) String() string {
	return strings.Join(a, ",")
}

func (a *csvFlag) Set(p string) error {
	*a = strings.Split(p, ",")
	return nil
}
func (a *csvFlag) Type() string {
	return "string"
}
