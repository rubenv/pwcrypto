package pwcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

func runCryptoTests(t *testing.T, a Algorithm) {
	assert := assert.New(t)

	assert.NotEqual("", a.ID())

	h, err := a.Hash("test")
	assert.NoError(err)
	assert.NotEqual("", h)

	ok, mustUpgrade, err := a.Check("test", h)
	assert.NoError(err)
	assert.True(ok)
	assert.False(mustUpgrade)

	ok, mustUpgrade, err = a.Check("bad", h)
	assert.NoError(err)
	assert.False(ok)
	assert.False(mustUpgrade)
}

func TestUpgrade(t *testing.T) {
	assert := assert.New(t)

	// We used to use null crypto (bad!)
	c := New(NullCrypto{})

	h1, err := c.Hash("test")
	assert.NoError(err)
	assert.NotEqual("", h1)

	valid, mustUpgrade, err := c.Check("test", h1)
	assert.NoError(err)
	assert.True(valid)
	assert.False(mustUpgrade)

	valid, mustUpgrade, err = c.Check("bad", h1)
	assert.NoError(err)
	assert.False(valid)
	assert.False(mustUpgrade)

	// Now we use PBKDF2
	c = New(
		NewPBKDF2Crypto(),
		NullCrypto{}, // Load support for null crypto, to recognize it
	)

	h2, err := c.Hash("test")
	assert.NoError(err)
	assert.NotEqual("", h2)

	assert.NotEqual(h1, h2)

	valid, mustUpgrade, err = c.Check("test", h2)
	assert.NoError(err)
	assert.True(valid)
	assert.False(mustUpgrade)

	valid, mustUpgrade, err = c.Check("bad", h2)
	assert.NoError(err)
	assert.False(valid)
	assert.False(mustUpgrade)

	// Old hashes are still recognized, but need an upgrade
	valid, mustUpgrade, err = c.Check("test", h1)
	assert.NoError(err)
	assert.True(valid)
	assert.True(mustUpgrade)

	valid, mustUpgrade, err = c.Check("bad", h1)
	assert.NoError(err)
	assert.False(valid)
	assert.False(mustUpgrade)

	// Check upgrades for PBKDF2
	oc := New(NewPBKDF2CryptoWithOptions(8192, 32, 24, []HashFunction{SHA1}))
	h3, err := oc.Hash("test")
	assert.NoError(err)

	valid, mustUpgrade, err = c.Check("test", h3)
	assert.NoError(err)
	assert.True(valid)
	assert.True(mustUpgrade)

	oc = New(NewPBKDF2CryptoWithOptions(4096, 32, 24, []HashFunction{SHA512}))
	h4, err := oc.Hash("test")
	assert.NoError(err)

	valid, mustUpgrade, err = c.Check("test", h4)
	assert.NoError(err)
	assert.True(valid)
	assert.True(mustUpgrade)
}
