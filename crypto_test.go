package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNullCrypto(t *testing.T) {
	runCryptoTests(t, NullCrypto{})
}

func TestPBKDF2Crypto(t *testing.T) {
	runCryptoTests(t, NewPBKDF2Crypto(8192, 32, 24))
}

func runCryptoTests(t *testing.T, a Algorithm) {
	assert := assert.New(t)

	assert.NotEqual("", a.ID())

	h, err := a.Hash("test")
	assert.NoError(err)
	assert.NotEqual("", h)

	ok, err := a.Check("test", h)
	assert.NoError(err)
	assert.True(ok)

	ok, err = a.Check("bad", h)
	assert.NoError(err)
	assert.False(ok)
}
