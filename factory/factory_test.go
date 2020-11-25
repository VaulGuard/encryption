package factory_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/VaulGuard/encryption"
	"testing"

	"github.com/VaulGuard/encryption/factory"
	"github.com/stretchr/testify/require"
)

var (
	secretKeyAlgorithms = []encryption.SecretKeyEncryption{
		encryption.ChaCha20Poly1305,
	}
	publicKeyAlgorithms = []encryption.PublicKeyEncryption{
		encryption.XSalsa20,
	}
)

func TestNewSecretKeyEncryption(t *testing.T) {
	assert := require.New(t)
	key := make([]byte, 32)
	rand.Read(key)

	t.Run("Success", func(t *testing.T) {
		for _, algo := range secretKeyAlgorithms {
			service, err := factory.NewSecretKeyEncryption(algo, key)
			assert.Nil(err)
			assert.NotNil(service)
			assert.Implements((*encryption.Service)(nil), service)
		}
	})

	t.Run("AlgorithmNotSupported", func(t *testing.T) {
		service, err := factory.NewSecretKeyEncryption(encryption.UnsupportedSecretKeyAlgorithm, key)
		assert.Error(err)
		assert.Nil(service)
		assert.True(errors.Is(encryption.ErrAlgorithmNotSupported, err))
	})
}

func TestNewSecretKeyGenerator(t *testing.T) {
	assert := require.New(t)
	buffer := bytes.NewBufferString("")
	key := make([]byte, 32)
	rand.Read(key)
	service, _ := factory.NewSecretKeyEncryption(encryption.ChaCha20Poly1305, key)

	t.Run("Success", func(t *testing.T) {
		for _, algo := range secretKeyAlgorithms {
			s, err := factory.NewSecretKeyGenerator(algo, buffer, service)
			assert.Nil(err)
			assert.NotNil(s)
			assert.Implements((*encryption.KeyGenerator)(nil), s)
		}
	})

	t.Run("AlgorithmNotSupported", func(t *testing.T) {
		service, err := factory.NewSecretKeyGenerator(encryption.UnsupportedPublicKeyAlgorithm, buffer, service)
		assert.Error(err)
		assert.Nil(service)
		assert.True(errors.Is(encryption.ErrAlgorithmNotSupported, err))
	})
}

func TestNewPublicKeyEncryption(t *testing.T) {
	assert := require.New(t)
	private := make([]byte, 32)
	public := make([]byte, 32)
	rand.Read(private)
	rand.Read(public)

	privateKey := bytes.NewBuffer(private)
	publicKey := bytes.NewBuffer(public)

	t.Run("Success", func(t *testing.T) {
		for _, algo := range publicKeyAlgorithms {
			service, err := factory.NewPublicKeyEncryption(algo, privateKey, publicKey)
			assert.Nil(err)
			assert.NotNil(service)
			assert.Implements((*encryption.Service)(nil), service)
		}
	})

	t.Run("AlgorithmNotSupported", func(t *testing.T) {
		service, err := factory.NewPublicKeyEncryption(encryption.UnsupportedPublicKeyAlgorithm, privateKey, publicKey)
		assert.Error(err)
		assert.Nil(service)
		assert.True(errors.Is(encryption.ErrAlgorithmNotSupported, err))
	})
}

func TestNewPublicKeyGenerator(t *testing.T) {
	assert := require.New(t)
	publicKey := bytes.NewBufferString("")
	privateKey := bytes.NewBuffer([]byte{})

	t.Run("Success", func(t *testing.T) {
		for _, algo := range publicKeyAlgorithms {
			s, err := factory.NewPublicKeyGenerator(algo, publicKey, privateKey)
			assert.Nil(err)
			assert.NotNil(s)
			assert.Implements((*encryption.KeyGenerator)(nil), s)
		}
	})

	t.Run("AlgorithmNotSupported", func(t *testing.T) {
		service, err := factory.NewPublicKeyGenerator(encryption.UnsupportedPublicKeyAlgorithm, publicKey, privateKey)
		assert.Error(err)
		assert.Nil(service)
		assert.True(errors.Is(encryption.ErrAlgorithmNotSupported, err))
	})
}
