package backend

import (
	"errors"
	"fmt"
	"strings"
)

type Crypto struct {
	preferred  string
	algorithms []Algorithm
}

func New(algorithms ...Algorithm) *Crypto {
	preferred := ""
	if len(algorithms) > 0 {
		preferred = algorithms[0].ID()
	}

	return &Crypto{
		preferred:  preferred,
		algorithms: algorithms,
	}
}

func (c *Crypto) Hash(input string) (string, error) {
	if len(c.algorithms) == 0 {
		return "", errors.New("No password crypto algorithms defined!")
	}

	alg := c.algorithms[0]
	hashed, err := alg.Hash(input)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%s", alg.ID(), hashed), nil
}

func (c *Crypto) Check(input, hashed string) (valid bool, mustUpgrade bool, err error) {
	parts := strings.SplitN(hashed, "|", 2)

	for _, a := range c.algorithms {
		if a.ID() == parts[0] {
			valid, err = a.Check(input, parts[1])
			if err != nil {
				return false, false, err
			}

			mustUpgrade = valid && a.ID() != c.preferred
			return valid, mustUpgrade, nil
		}
	}

	return false, false, nil
}
