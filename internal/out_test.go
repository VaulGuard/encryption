package internal_test

import (
	"bytes"
	"errors"
	"github.com/VaulGuard/encryption/internal"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type mockWriter struct {
	mock.Mock
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func TestWriteKey_Unit(t *testing.T) {
	t.Parallel()
	key := []byte("example bytes")
	assert := require.New(t)
	t.Run("WritingErrors", func(t *testing.T) {
		w := new(mockWriter)
		w.On("Write", key).Once().Return(0, errors.New("error occurred"))
		err := internal.WriteKey(w, key)
		assert.Error(err)
		assert.Equal("error occurred", err.Error())
	})

	t.Run("NotEnoughBytesWritten", func(t *testing.T) {
		w := new(mockWriter)
		w.On("Write", key).Once().Return(1, nil)
		err := internal.WriteKey(w, key)
		assert.Error(err)
		assert.Equal(internal.ErrNotEnoughBytesWritten.Error(), err.Error())
	})

	t.Run("Success", func(t *testing.T) {
		w := new(mockWriter)
		w.On("Write", key).Once().Return(len(key), nil)
		err := internal.WriteKey(w, key)
		assert.Nil(err)
	})
}

func TestWriteKey(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	buffer := bytes.NewBufferString("")
	key := []byte("example bytes")

	err := internal.WriteKey(buffer, key)
	assert.Nil(err)
	assert.Equal("example bytes", buffer.String())
}

func TestSetOut(t *testing.T) {
	t.Parallel()
	assert := require.New(t)
	key := []byte("example bytes")
	var out []byte
	internal.SetOut(&out, key)

	assert.Equal(out, key)
}
