package pwcrypto

import (
	"log"
	"testing"
)

func TestNullCrypto(t *testing.T) {
	runCryptoTests(t, NullCrypto{})
}

func TestPBKDF2Crypto(t *testing.T) {
	runCryptoTests(t, NewPBKDF2Crypto())
}

func TestSHA1Crypto(t *testing.T) {
	runCryptoTests(t, NewSHA1Crypto())
}

func TestSHA256Crypto(t *testing.T) {
	runCryptoTests(t, NewSHA256Crypto())
}

func TestScryptCrypto(t *testing.T) {
	runCryptoTests(t, NewScryptCrypto())
}

func TestArgon2Crypto(t *testing.T) {
	runCryptoTests(t, NewArgon2Crypto())
}

func runCryptoTests(t *testing.T, a Algorithm) {
	notEqual(t, "", a.ID())

	h, err := a.Hash("test")
	noError(t, err)
	notEqual(t, "", h)

	log.Println(h)

	ok, mustUpgrade, err := a.Check("test", h)
	noError(t, err)
	equal(t, ok, true)
	equal(t, mustUpgrade, false)

	ok, mustUpgrade, err = a.Check("bad", h)
	noError(t, err)
	equal(t, ok, false)
	equal(t, mustUpgrade, false)
}

func TestUpgrade(t *testing.T) {
	// We used to use null crypto (bad!)
	c := New(NullCrypto{})

	h1, err := c.Hash("test")
	noError(t, err)
	notEqual(t, "", h1)

	valid, mustUpgrade, err := c.Check("test", h1)
	noError(t, err)
	equal(t, valid, true)
	equal(t, mustUpgrade, false)

	valid, mustUpgrade, err = c.Check("bad", h1)
	noError(t, err)
	equal(t, valid, false)
	equal(t, mustUpgrade, false)

	// Now we use PBKDF2
	c = New(
		NewPBKDF2Crypto(),
		NullCrypto{}, // Load support for null crypto, to recognize it
	)

	h2, err := c.Hash("test")
	noError(t, err)
	notEqual(t, "", h2)

	notEqual(t, h1, h2)

	valid, mustUpgrade, err = c.Check("test", h2)
	noError(t, err)
	equal(t, valid, true)
	equal(t, mustUpgrade, false)

	valid, mustUpgrade, err = c.Check("bad", h2)
	noError(t, err)
	equal(t, valid, false)
	equal(t, mustUpgrade, false)

	// Old hashes are still recognized, but need an upgrade
	valid, mustUpgrade, err = c.Check("test", h1)
	noError(t, err)
	equal(t, valid, true)
	equal(t, mustUpgrade, true)

	valid, mustUpgrade, err = c.Check("bad", h1)
	noError(t, err)
	equal(t, valid, false)
	equal(t, mustUpgrade, false)

	// Check upgrades for PBKDF2
	oc := New(NewPBKDF2CryptoWithOptions(8192, 32, 24, []HashFunction{SHA1}))
	h3, err := oc.Hash("test")
	noError(t, err)

	valid, mustUpgrade, err = c.Check("test", h3)
	noError(t, err)
	equal(t, valid, true)
	equal(t, mustUpgrade, true)

	oc = New(NewPBKDF2CryptoWithOptions(4096, 32, 24, []HashFunction{SHA512}))
	h4, err := oc.Hash("test")
	noError(t, err)

	valid, mustUpgrade, err = c.Check("test", h4)
	noError(t, err)
	equal(t, valid, true)
	equal(t, mustUpgrade, true)
}
