package pwcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type PBKDF2Crypto struct {
	iter    int
	keyLen  int
	saltLen int
	hashFns []HashFunction
}

var _ Algorithm = PBKDF2Crypto{}

// Create PBKDF2 with recommended options
func NewPBKDF2Crypto() PBKDF2Crypto {
	return NewPBKDF2CryptoWithOptions(8192, 32, 24, []HashFunction{
		SHA512,
		SHA256,
		SHA1,
	})
}

// Create PBKDF2C with given number of iterations, key length, salt length and
// accepted hash functions.
//
// First hash function is the preferred one which will be used
// for new passwords, all other ones will signal the need for an
// upgrade.
func NewPBKDF2CryptoWithOptions(iter, keyLen, saltLen int, hashFns []HashFunction) PBKDF2Crypto {
	return PBKDF2Crypto{
		iter:    iter,
		keyLen:  keyLen,
		saltLen: saltLen,
		hashFns: hashFns,
	}
}

func (a PBKDF2Crypto) ID() string {
	return "pbkdf2"
}

func (a PBKDF2Crypto) Hash(input string) (string, error) {
	if len(a.hashFns) == 0 {
		return "", fmt.Errorf("No hash functions supplied for PBKDF2")
	}

	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashFn := a.hashFns[0]
	hashed := pbkdf2.Key([]byte(input), salt, a.iter, a.keyLen, hashFn.Hash())
	hash := fmt.Sprintf("%x|%x|%d|%d|%s", hashed, salt, a.iter, a.keyLen, hashFn)
	return hash, nil
}

func (a PBKDF2Crypto) Check(input, hashed string) (bool, bool, error) {
	parts := strings.Split(hashed, "|")
	if len(parts) != 5 {
		return false, false, errors.New("Not a good hash value!")
	}

	toMatch := parts[0]
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, false, err
	}

	iter, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, false, err
	}

	keyLen, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, false, err
	}

	hashFn, err := ParseHashFunction(parts[4])
	if err != nil {
		return false, false, err
	}

	found := false
	for _, hf := range a.hashFns {
		if hf == hashFn {
			found = true
			break
		}
	}
	if !found {
		return false, false, nil
	}

	inputhashed := pbkdf2.Key([]byte(input), salt, iter, keyLen, hashFn.Hash())

	valid := fmt.Sprintf("%x", inputhashed) == toMatch
	mustUpgrade := valid && (len(salt) != a.saltLen || iter != a.iter || keyLen != a.keyLen || hashFn != a.hashFns[0])
	return valid, mustUpgrade, nil
}
