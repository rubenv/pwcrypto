package pwcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type ScryptCrypto struct {
	saltLen    int
	cpuMemCost int
	r          int
	p          int
	keyLen     int
}

var _ Algorithm = ScryptCrypto{}

// Create Scrypt with recommended options
func NewScryptCrypto() ScryptCrypto {
	return NewScryptCryptoWithOptions(32, 32768, 8, 1, 32)
}

// Create ScryptC with given number of iterations, key length, salt length and
// accepted hash functions.
//
// First hash function is the preferred one which will be used
// for new passwords, all other ones will signal the need for an
// upgrade.
func NewScryptCryptoWithOptions(saltLen, cpuMemCost, r, p, keyLen int) ScryptCrypto {
	return ScryptCrypto{
		saltLen:    saltLen,
		cpuMemCost: cpuMemCost,
		r:          r,
		p:          p,
		keyLen:     keyLen,
	}
}

func (a ScryptCrypto) ID() string {
	return "Scrypt"
}

func (a ScryptCrypto) Hash(input string) (string, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashed, err := scrypt.Key([]byte(input), salt, a.cpuMemCost, a.r, a.p, a.keyLen)
	if err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%x|%x|%d|%d|%d|%d", hashed, salt, a.cpuMemCost, a.r, a.p, a.keyLen)
	return hash, nil
}

func (a ScryptCrypto) Check(input, hashed string) (bool, bool, error) {
	parts := strings.Split(hashed, "|")
	if len(parts) != 6 {
		return false, false, errors.New("Not a good hash value!")
	}

	toMatch := parts[0]
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, false, err
	}

	cpuMemCost, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, false, err
	}
	r, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, false, err
	}
	p, err := strconv.Atoi(parts[4])
	if err != nil {
		return false, false, err
	}
	keyLen, err := strconv.Atoi(parts[5])
	if err != nil {
		return false, false, err
	}

	inputhashed, err := scrypt.Key([]byte(input), salt, cpuMemCost, r, p, keyLen)
	if err != nil {
		return false, false, err
	}

	valid := fmt.Sprintf("%x", inputhashed) == toMatch
	mustUpgrade := valid && (len(salt) != a.saltLen || cpuMemCost != a.cpuMemCost || r != a.r || p != a.p || keyLen != a.keyLen)
	return valid, mustUpgrade, nil
}
