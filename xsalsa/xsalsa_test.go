package xsalsa_test

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/VaulGuard/encryption/xsalsa"
	"golang.org/x/crypto/nacl/box"
)

func TestPublicKeyService(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	public, private, err := box.GenerateKey(rand.Reader)

	assert.Nilf(err, "Error while generating public and private key pair: %v\n", err)

	publicKeyBuf := bytes.NewBuffer(public[:])
	privateKeyBuf := bytes.NewBuffer(private[:])

	service, err := xsalsa.New(publicKeyBuf, privateKeyBuf)
	assert.Nilf(err, "Error while creating public key encryption service: %v\n", err)

	t.Run("Encrypt", func(t *testing.T) {
		data, err := service.EncryptString("Hello World")
		assert.Nilf(err, "Error while encrypting: %v\n", err)
		assert.False(data == nil || len(data) == 0, "Error while encrypting, no encrypted data\n")
	})

	t.Run("Decryption", func(t *testing.T) {
		data, err := service.EncryptString("Hello World")
		assert.Nilf(err, "Error while encrypting: %v\n", err)
		assert.Falsef(data == nil || len(data) == 0, "Error while encrypting, no encrypted data\n")
		message, err := service.DecryptString(data)
		assert.Nilf(err, "Error while decrypting: %v\n", err)

		assert.Truef(message == "Hello World", "Error while decrypting: Expected message \"Hello World\", Given: %s", message)
	})

}
