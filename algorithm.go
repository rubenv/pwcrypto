package backend

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type Algorithm interface {
	ID() string
	Hash(input string) (string, error)
	Check(input, hashed string) (bool, error)
}

type NullCrypto struct {
}

func (n NullCrypto) ID() string {
	return "null"
}

func (n NullCrypto) Hash(input string) (string, error) {
	return input, nil
}

func (n NullCrypto) Check(input, hashed string) (bool, error) {
	return input == hashed, nil
}

type PBKDF2Crypto struct {
	iter    int
	keyLen  int
	saltLen int
}

func NewPBKDF2Crypto(iter, keyLen, saltLen int) PBKDF2Crypto {
	return PBKDF2Crypto{
		iter:    iter,
		keyLen:  keyLen,
		saltLen: saltLen,
	}
}

func (a PBKDF2Crypto) ID() string {
	return "pbkdf2"
}

func (a PBKDF2Crypto) Hash(input string) (string, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashed := pbkdf2.Key([]byte(input), salt, a.iter, a.keyLen, sha1.New)
	hash := fmt.Sprintf("%x|%x|%d|%d", hashed, salt, a.iter, a.keyLen)
	return hash, nil
}

func (a PBKDF2Crypto) Check(input, hashed string) (bool, error) {
	parts := strings.Split(hashed, "|")
	if len(parts) != 4 {
		return false, errors.New("Not a good hash value!")
	}

	toMatch := parts[0]
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	iter, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, err
	}

	keyLen, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, err
	}

	inputhashed := pbkdf2.Key([]byte(input), salt, iter, keyLen, sha1.New)

	if fmt.Sprintf("%x", inputhashed) == toMatch {
		return true, nil
	}

	return false, nil
}
