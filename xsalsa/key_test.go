package xsalsa_test

import (
	"bytes"
	"github.com/VaulGuard/encryption/xsalsa"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKeyPairGenerator(t *testing.T) {
	t.Parallel()
	asserts := require.New(t)

	t.Run("Generate", func(t *testing.T) {
		publicBuffer := bytes.NewBuffer(make([]byte, 0, 32))
		privateBuffer := bytes.NewBuffer(make([]byte, 0, 32))

		generator := xsalsa.NewSalsaKeyGenerator(publicBuffer, privateBuffer)
		asserts.Nilf(generator.Generate(), "Error while generating public and private key pair")
		asserts.Equal(publicBuffer.Len(), 32)
		asserts.Equal(privateBuffer.Len(), 32)
	})

	t.Run("GenerateWithOutput", func(t *testing.T) {
		publicKeyOut := make([]byte, 0, xsalsa.PublicKeyLength)
		privateKeyOut := make([]byte, 0, xsalsa.PrivateKeyLength)

		publicBuffer := bytes.NewBuffer(make([]byte, 0, xsalsa.PublicKeyLength))
		privateBuffer := bytes.NewBuffer(make([]byte, 0, xsalsa.PrivateKeyLength))

		generator := xsalsa.NewSalsaKeyGenerator(publicBuffer, privateBuffer)
		asserts.Nilf(generator.Generate(&publicKeyOut, &privateKeyOut), "Error while generating public and private key pair")
		asserts.Equal(publicBuffer.Len(), xsalsa.PublicKeyLength)
		asserts.Equal(privateBuffer.Len(), xsalsa.PrivateKeyLength)

		asserts.EqualValues(publicBuffer.Bytes(), publicKeyOut)
		asserts.EqualValues(privateBuffer.Bytes(), privateKeyOut)
	})
}
