package encryption

import (
	"crypto/rand"
	"io"

	"github.com/VaulGuard/encryption/chacha"
	"github.com/VaulGuard/encryption/xsalsa"
)

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
