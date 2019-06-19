package backend

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type SHA256Crypto struct {
	saltLen int
}

var _ Algorithm = SHA256Crypto{}

// Create PBKDF2 with recommended options
func NewSHA256Crypto() SHA256Crypto {
	return NewSHA256CryptoWithOptions(32)
}

func NewSHA256CryptoWithOptions(saltLen int) SHA256Crypto {
	return SHA256Crypto{
		saltLen: saltLen,
	}
}

func (a SHA256Crypto) ID() string {
	return "sha256"
}

func (a SHA256Crypto) Hash(input string) (string, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashed := a.hashVal(salt, input)
	return fmt.Sprintf("%s|%x", hashed, salt), nil
}

func (a SHA256Crypto) Check(input, hashed string) (bool, bool, error) {
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

func (a SHA256Crypto) hashVal(salt []byte, input string) string {
	h := sha256.New()
	h.Write(salt)
	io.WriteString(h, input)
	return fmt.Sprintf("%x", h.Sum(nil))
}
