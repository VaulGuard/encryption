package encryption

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/VaulGuard/encryption/chacha"
	"github.com/VaulGuard/encryption/xsalsa"
)

type (
	SecretKeyEncryption string
	PublicKeyEncryption string
)

const (
	ChaCha20Poly1305 SecretKeyEncryption = "chacha20poly1305"

	XSalsa20 PublicKeyEncryption = "xsalsa20"
)

var (
	ErrAlgorithmNotSupported = errors.New("algorithm is not supported")
	ErrNotEnoughBytes        = errors.New("not enough bytes read from crypto random source")
	ErrKeyLength             = errors.New("key has to be 32 bytes long")
)

// Service - Interface for encryption and decryption
type Service interface {
	Encrypt(dst, msg []byte) ([]byte, error)
	EncryptString(msg string) ([]byte, error)
	Decrypt(dst, msg []byte) ([]byte, error)
	DecryptString(msg []byte) (string, error)
}

func NewSecretKeyEncryption(algo SecretKeyEncryption, key interface{}) (Service, error) {
	switch algo {
	case ChaCha20Poly1305:
		return chacha.New(key.([]byte))
	}

	return nil, ErrAlgorithmNotSupported
}

func NewSecretKeyGenerator(algo SecretKeyEncryption, w io.Writer, encryptor Service) (KeyGenerator, error) {
	switch algo {
	case ChaCha20Poly1305:
		return chacha.NewChaChaKey(w, encryptor, rand.Reader), nil
	}

	return nil, ErrAlgorithmNotSupported
}

func NewPublicKeyEncryption(algo PublicKeyEncryption, private, public interface{}) (Service, error) {
	switch algo {
	case XSalsa20:
		return xsalsa.New(public.(io.Reader), private.(io.Reader))
	}

	return nil, ErrAlgorithmNotSupported
}

func NewPublicKeyGenerator(algo PublicKeyEncryption, public, private io.Writer) (KeyGenerator, error) {
	switch algo {
	case XSalsa20:
		return xsalsa.NewSalsaKeyGenerator(public, private), nil
	}

	return nil, ErrAlgorithmNotSupported
}
