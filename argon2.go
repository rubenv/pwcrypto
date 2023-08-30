package pwcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Crypto struct {
	saltLen int
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

var _ Algorithm = Argon2Crypto{}

// Create Argon2Crypto with recommended options
func NewArgon2Crypto() Argon2Crypto {
	return NewArgon2CryptoWithOptions(32, 2, 256*1024, 4, 32)
}

// Create Argon2Crypto with given salt length, time, memory, threads and key
// length.
func NewArgon2CryptoWithOptions(saltLen int, time, memory uint32, threads uint8, keyLen uint32) Argon2Crypto {
	return Argon2Crypto{
		saltLen: saltLen,
		time:    time,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
	}
}

func (a Argon2Crypto) ID() string {
	return "argon2"
}

func (a Argon2Crypto) Hash(input string) (string, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hashed := argon2.IDKey([]byte(input), salt, a.time, a.memory, a.threads, a.keyLen)
	hash := fmt.Sprintf("%x|%x|%d|%d|%d|%d", hashed, salt, a.time, a.memory, a.threads, a.keyLen)
	return hash, nil
}

func (a Argon2Crypto) Check(input, hashed string) (bool, bool, error) {
	parts := strings.Split(hashed, "|")
	if len(parts) != 6 {
		return false, false, errors.New("Not a good hash value!")
	}

	toMatch := parts[0]
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, false, err
	}

	time, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, false, err
	}
	memory, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, false, err
	}
	threads, err := strconv.Atoi(parts[4])
	if err != nil {
		return false, false, err
	}
	keyLen, err := strconv.Atoi(parts[5])
	if err != nil {
		return false, false, err
	}

	inputhashed := argon2.IDKey([]byte(input), salt, uint32(time), uint32(memory), uint8(threads), uint32(keyLen))

	valid := fmt.Sprintf("%x", inputhashed) == toMatch
	mustUpgrade := valid && (len(salt) != a.saltLen ||
		uint32(time) != a.time ||
		uint32(memory) != a.memory ||
		uint8(threads) != a.threads ||
		uint32(keyLen) != a.keyLen)
	return valid, mustUpgrade, nil
}
