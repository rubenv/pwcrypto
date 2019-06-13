package backend

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strconv"
)

//  SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512

type HashFunction int

const (
	SHA1 HashFunction = 0
	//SHA224 HashFunction = 1
	SHA256 HashFunction = 2
	//SHA384 HashFunction = 3
	SHA512 HashFunction = 4
)

func (h HashFunction) Hash() func() hash.Hash {
	switch h {
	case SHA1:
		return sha1.New
	//case SHA224:
	//	return sha224.New
	case SHA256:
		return sha256.New
	//case SHA384:
	//return sha384.New
	case SHA512:
		return sha512.New
	default:
		panic("Invalid hash function")
	}
}

func (h HashFunction) String() string {
	return fmt.Sprintf("%d", h)
}

func ParseHashFunction(in string) (HashFunction, error) {
	hashFn, err := strconv.Atoi(in)
	if err != nil {
		return 0, err
	}

	switch hashFn {
	case 0:
		return SHA1, nil
	case 2:
		return SHA256, nil
	case 4:
		return SHA512, nil
	default:
		return 0, fmt.Errorf("Unknown hash function: %s", in)
	}
}
