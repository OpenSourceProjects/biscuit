package flags

import (
	"fmt"
	"net/url"
)

type URL url.URL

func (a URL) String() string {
	u := url.URL(a)
	return u.String()
}

func (a *URL) Set(p string) error {
	u, err := url.Parse(p)
	if err != nil {
		return fmt.Errorf("could not parse URL: %w", err)
	}
	*a = URL(*u)
	return nil
}

func (a *URL) Type() string {
	return "string"
}
