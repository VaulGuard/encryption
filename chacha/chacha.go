package chacha

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/VaulGuard/encryption"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SecretKeyLength = chacha20poly1305.KeySize
)

type secretKeyEncryption struct {
	cipher cipher.AEAD
	key    []byte
}

func New(key []byte) (encryption.Service, error) {
	c, err := chacha20poly1305.NewX(key)

	if err != nil {
		return nil, err
	}

	return secretKeyEncryption{
		key:    key,
		cipher: c,
	}, nil
}

func (s secretKeyEncryption) EncryptString(msg string) ([]byte, error) {
	capacity := s.cipher.NonceSize() + len(msg) + s.cipher.Overhead()

	dst := make([]byte, s.cipher.NonceSize(), capacity)

	return s.Encrypt(dst, []byte(msg))
}

func (s secretKeyEncryption) Encrypt(dst, msg []byte) ([]byte, error) {
	capacity := s.cipher.NonceSize() + len(msg) + s.cipher.Overhead()

	if len(dst) != s.cipher.NonceSize() || cap(dst) != capacity {
		return nil, fmt.Errorf("not enough bytes in dst, expected %d, given %d", capacity, cap(dst))
	}

	n, err := rand.Read(dst)

	if err != nil {
		return nil, err
	}

	if n != len(dst) {
		return nil, errors.New("cannot generate random nonce")
	}

	return s.cipher.Seal(dst, dst, msg, nil), nil
}

func (s secretKeyEncryption) Decrypt(dst, msg []byte) ([]byte, error) {
	if len(msg) < s.cipher.NonceSize() {
		return nil, errors.New("size of message is less than nonce size")
	}
	nonce, ciphertext := msg[:s.cipher.NonceSize()], msg[s.cipher.NonceSize():]

	decrypted, err := s.cipher.Open(dst, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func (s secretKeyEncryption) DecryptString(msg []byte) (string, error) {
	message, err := s.Decrypt(nil, msg)

	if err != nil {
		return "", err
	}

	return string(message), nil
}
