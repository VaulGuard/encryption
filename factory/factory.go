package encryption

import (
	"crypto/rand"
	"io"

	"github.com/VaulGuard/encryption"
	"github.com/VaulGuard/encryption/chacha"
	"github.com/VaulGuard/encryption/xsalsa"
)

func NewSecretKeyEncryption(algo encryption.SecretKeyEncryption, key interface{}) (encryption.Service, error) {
	switch algo {
	case encryption.ChaCha20Poly1305:
		return chacha.New(key.([]byte))
	}

	return nil, encryption.ErrAlgorithmNotSupported
}

func NewSecretKeyGenerator(algo encryption.SecretKeyEncryption, w io.Writer, encryptor encryption.Service) (encryption.KeyGenerator, error) {
	switch algo {
	case encryption.ChaCha20Poly1305:
		return chacha.NewChaChaKey(w, encryptor, rand.Reader), nil
	}

	return nil, encryption.ErrAlgorithmNotSupported
}

func NewPublicKeyEncryption(algo encryption.PublicKeyEncryption, private, public interface{}) (encryption.Service, error) {
	switch algo {
	case encryption.XSalsa20:
		return xsalsa.New(public.(io.Reader), private.(io.Reader))
	}

	return nil, encryption.ErrAlgorithmNotSupported
}

func NewPublicKeyGenerator(algo encryption.PublicKeyEncryption, public, private io.Writer) (encryption.KeyGenerator, error) {
	switch algo {
	case encryption.XSalsa20:
		return xsalsa.NewSalsaKeyGenerator(public, private), nil
	}

	return nil, encryption.ErrAlgorithmNotSupported
}
