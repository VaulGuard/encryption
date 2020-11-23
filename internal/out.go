package internal

import (
	"errors"
	"io"
)

var (
	ErrNotEnoughBytesWritten = errors.New("not enough bytes written to io.Writer")
)

func SetOut(out interface{}, value []byte) {
	bytes := out.(*[]byte)
	*bytes = value
}

func WriteKey(w io.Writer, key []byte) error {
	n, err := w.Write(key[:])

	if err != nil {
		return err
	}

	if n != len(key) {
		return ErrNotEnoughBytesWritten
	}

	return nil
}
