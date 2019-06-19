package pwcrypto

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type SHA1Crypto struct {
	saltLen int
}

var _ Algorithm = SHA1Crypto{}

// Create PBKDF2 with recommended options
func NewSHA1Crypto() SHA1Crypto {
	return NewSHA1CryptoWithOptions(32)
}

func NewSHA1CryptoWithOptions(saltLen int) SHA1Crypto {
	return SHA1Crypto{
		saltLen: saltLen,
	}
}

func (a SHA1Crypto) ID() string {
	return "sha1"
}

func (a SHA1Crypto) Hash(input string) (string, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashed := a.hashVal(salt, input)
	return fmt.Sprintf("%s|%x", hashed, salt), nil
}

func (a SHA1Crypto) Check(input, hashed string) (bool, bool, error) {
	parts := strings.Split(hashed, "|")
	if len(parts) != 2 {
		return false, false, errors.New("Not a good hash value!")
	}

	toMatch := parts[0]
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, false, err
	}

	inputhashed := a.hashVal(salt, input)

	valid := inputhashed == toMatch
	mustUpgrade := valid && len(salt) != a.saltLen
	return valid, mustUpgrade, nil
}

func (a SHA1Crypto) hashVal(salt []byte, input string) string {
	h := sha1.New()
	h.Write(salt)
	io.WriteString(h, input)
	return fmt.Sprintf("%x", h.Sum(nil))
}
