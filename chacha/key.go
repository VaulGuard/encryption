package chacha

import (
	"github.com/VaulGuard/encryption"
	"github.com/VaulGuard/encryption/internal"
	"io"
)

type chachaKeyGenerator struct {
	encryption encryption.Service
	random     io.Reader
	out        io.Writer
}

func NewChaChaKey(w io.Writer, service encryption.Service, random io.Reader) encryption.KeyGenerator {
	return chachaKeyGenerator{
		encryption: service,
		random:     random,
		out:        w,
	}
}

func (s chachaKeyGenerator) Generate(out ...interface{}) error {
	key := make([]byte, SecretKeyLength)
	n, err := s.random.Read(key)

	if err != nil {
		return err
	}

	if n != SecretKeyLength {
		return encryption.ErrNotEnoughBytes
	}

	if len(out) == 1 {
		internal.SetOut(out[0], key)
	}

	enc, err := s.encryption.Encrypt(nil, key)

	if err != nil {
		return err
	}

	return internal.WriteKey(s.out, enc)
}
