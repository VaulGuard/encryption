package chacha_test

import (
	"crypto/rand"
	"testing"

	"github.com/VaulGuard/encryption/chacha"
	"github.com/stretchr/testify/require"
)

func TestChaChaSecretKeyEncryption(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	key := make([]byte, 32)

	_, err := rand.Read(key)

	assert.Nilf(err, "Cannot generate random key: %v\n", err)
	service, err := chacha.New(key)

	assert.Nilf(err, "Cannot create encryption service: %v\n", err)

	t.Run("Encryption", func(t *testing.T) {
		encryptedBytes, err := service.EncryptString("Hello World")
		assert.Nilf(err, "Cannot encrypt text: %v", err)
		str, err := service.DecryptString(encryptedBytes)
		assert.Nilf(err, "Decryption failed: %v", err)
		assert.Equal("Hello World", str, "Starting string is not equal to decrypted string\n")
	})

	t.Run("SmallMessageInDecryption", func(t *testing.T) {
		dst := make([]byte, 24, 25)
		_, err := service.Encrypt(dst, []byte("Hello World"))
		assert.NotNil(err)
	})

	t.Run("DecryptionWithSmallMessageSize", func(t *testing.T) {
		data := make([]byte, 12)

		_, _ = rand.Read(data)

		_, err := service.DecryptString(data)

		assert.NotNil(err)
	})
}
