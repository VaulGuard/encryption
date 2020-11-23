package xsalsa_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/VaulGuard/encryption/xsalsa"
	"golang.org/x/crypto/nacl/box"
)

func TestPublicKeyService(t *testing.T) {
	t.Parallel()
	public, private, err := box.GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("Error while generating public and private key pair: %v\n", err)
	}

	publicKeyBuf := bytes.NewBuffer(public[:])
	privateKeyBuf := bytes.NewBuffer(private[:])

	service, err := xsalsa.New(publicKeyBuf, privateKeyBuf)

	if err != nil {
		t.Fatalf("Error while creating public key encryption service: %v\n", err)
	}

	t.Run("Encrypt", func(t *testing.T) {
		data, err := service.EncryptString("Hello World")

		if err != nil {
			t.Fatalf("Error while encrypting: %v\n", err)
		}

		if data == nil || len(data) == 0 {
			t.Fatalf("Error while encrypting, no encrypted data\n")
		}
	})

	t.Run("Decryption", func(t *testing.T) {
		data, err := service.EncryptString("Hello World")

		if err != nil {
			t.Fatalf("Error while encrypting: %v\n", err)
		}

		if data == nil || len(data) == 0 {
			t.Fatalf("Error while encrypting, no encrypted data\n")
		}

		message, err := service.DecryptString(data)

		if err != nil {
			t.Fatalf("Error while decrypting: %v\n", err)
		}

		if message != "Hello World" {
			t.Fatalf("Error while decrypting: Expected message \"Hello World\", Given: %s", message)
		}
	})

}
