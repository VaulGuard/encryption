package encryption

import (
	"errors"
)

var (
	ErrNotEnoughBytes = errors.New("not enough bytes read from crypto random source")
	ErrKeyLength      = errors.New("key has to be 32 bytes long")
)

// Service - Interface for encryption and decryption
type Service interface {
	Encrypt(dst, msg []byte) ([]byte, error)
	EncryptString(msg string) ([]byte, error)
	Decrypt(dst, msg []byte) ([]byte, error)
	DecryptString(msg []byte) (string, error)
}
