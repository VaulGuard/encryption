package internal_test

import (
	"crypto/rand"
	"errors"
	"github.com/VaulGuard/encryption/internal"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type ReaderMock struct {
	mock.Mock
}

func (r *ReaderMock) Read(p []byte) (n int, err error) {
	args := r.Called(p)
	return args.Int(0), args.Error(1)
}

func TestGenerateRandomKey_Integration(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	randomBytes := make([]byte, 32)
	err := internal.GenerateRandomKey(randomBytes, rand.Reader)
	assert.Nil(err)

	for _, b := range randomBytes {
		assert.Greater(b, byte(0))
	}
}

func TestGenerateRandomKey(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	t.Run("ReaderReturnsError", func(t *testing.T) {
		reader := new(ReaderMock)
		randomBytes := make([]byte, 32)
		reader.On("Read", randomBytes).Return(0, errors.New("error occurred"))
		assert.Error(internal.GenerateRandomKey(randomBytes, reader))
		reader.AssertExpectations(t)
	})

	t.Run("GeneratesRandomBytes", func(t *testing.T) {
		reader := new(ReaderMock)
		randomBytes := make([]byte, 32)
		reader.On("Read", randomBytes).Return(32, nil)
		rand.Read(randomBytes)
		assert.Nil(internal.GenerateRandomKey(randomBytes, reader))
		reader.AssertExpectations(t)
	})

}
