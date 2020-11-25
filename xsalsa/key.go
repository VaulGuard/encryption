package xsalsa

import (
	"crypto/rand"
	"io"

	"github.com/VaulGuard/encryption"
	"github.com/VaulGuard/encryption/internal"
	"golang.org/x/crypto/nacl/box"
)

const (
	PublicKeyLength  = 32
	PrivateKeyLength = 32
)

type xsalsaKeyGenerator struct {
	public  io.Writer
	private io.Writer
}

func NewSalsaKeyGenerator(public, private io.Writer) encryption.KeyGenerator {
	return xsalsaKeyGenerator{
		public:  public,
		private: private,
	}
}

func (g xsalsaKeyGenerator) Generate(out ...interface{}) error {
	public, private, err := box.GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	if err := internal.WriteKey(g.public, public[:]); err != nil {
		return err
	}

	if err := internal.WriteKey(g.private, private[:]); err != nil {
		return err
	}

	if len(out) == 2 {
		internal.SetOut(out[0], public[:])
		internal.SetOut(out[1], private[:])
	}

	return nil
}
