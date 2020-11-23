package xsalsa

import (
	"crypto/rand"
	"errors"
	"github.com/VaulGuard/encryption"
	"github.com/VaulGuard/encryption/internal"
	"golang.org/x/crypto/nacl/box"
	"io"
)

func New(publicKey, privateKey io.Reader) (encryption.Service, error) {
	var publicKeyBytes [32]byte
	var privateKeyBytes [32]byte

	if err := internal.GenerateRandomKey(publicKeyBytes[:], publicKey); err != nil {
		return nil, err
	}

	if err := internal.GenerateRandomKey(privateKeyBytes[:], privateKey); err != nil {
		return nil, err
	}

	return publicKeyEncryption{
		privateKey: &privateKeyBytes,
		publicKey:  &publicKeyBytes,
	}, nil
}

type publicKeyEncryption struct {
	privateKey *[32]byte
	publicKey  *[32]byte
}

func (p publicKeyEncryption) Encrypt(dst, msg []byte) ([]byte, error) {
	return box.SealAnonymous(dst, msg, p.publicKey, rand.Reader)
}

func (p publicKeyEncryption) EncryptString(msg string) ([]byte, error) {
	return p.Encrypt(nil, []byte(msg))
}

func (p publicKeyEncryption) Decrypt(dst, msg []byte) ([]byte, error) {
	message, ok := box.OpenAnonymous(dst, msg, p.publicKey, p.privateKey)

	if !ok {
		return nil, errors.New("decryption failed")
	}

	return message, nil
}

func (p publicKeyEncryption) DecryptString(msg []byte) (string, error) {
	message, err := p.Decrypt(nil, msg)

	if err != nil {
		return "", err
	}

	return string(message), nil
}
