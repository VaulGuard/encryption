package chacha_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/VaulGuard/encryption/chacha"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type encryptionService struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
	mock.Mock
}

func (e *encryptionService) Encrypt(dst, msg []byte) ([]byte, error) {
	args := e.Called(dst, msg)
	return args.Get(0).([]byte), args.Error(1)
}

func (e *encryptionService) EncryptString(msg string) ([]byte, error) {
	args := e.Called(msg)
	return args.Get(0).([]byte), args.Error(1)
}

func (e *encryptionService) Decrypt(dst, msg []byte) ([]byte, error) {
	args := e.Called(dst, msg)
	return args.Get(0).([]byte), args.Error(1)
}

func (e *encryptionService) DecryptString(msg []byte) (string, error) {
	args := e.Called(msg)
	return args.String(0), args.Error(1)
}

func TestSecretKeyGenerator(t *testing.T) {
	t.Parallel()
	asserts := require.New(t)
	encrypted := make([]byte, 48)
	rand.Read(encrypted)

	t.Run("Generate", func(t *testing.T) {
		secretBuffer := bytes.NewBuffer(make([]byte, 0, chacha.SecretKeyLength))
		service := new(encryptionService)
		service.On("Encrypt", []byte(nil), mock.MatchedBy(func(data []byte) bool {
			return len(data) == chacha.SecretKeyLength
		})).Return(encrypted, nil)
		secretGenerator := chacha.NewChaChaKey(secretBuffer, service, rand.Reader)
		asserts.Nil(secretGenerator.Generate())
	})

	t.Run("GenerateWithOutput", func(t *testing.T) {
		secretBuffer := bytes.NewBuffer(make([]byte, 0, chacha.SecretKeyLength))
		out := make([]byte, 0, chacha.SecretKeyLength)
		service := new(encryptionService)
		service.On("Encrypt", []byte(nil), mock.MatchedBy(func(data []byte) bool {
			return len(data) == chacha.SecretKeyLength
		})).Return(encrypted, nil)

		secretGenerator := chacha.NewChaChaKey(secretBuffer, service, rand.Reader)
		asserts.Nil(secretGenerator.Generate(&out))
		asserts.Len(out, chacha.SecretKeyLength)
		asserts.NotEqualValues(secretBuffer.Bytes(), out)
	})
}
