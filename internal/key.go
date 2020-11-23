package internal

import "io"

func GenerateRandomKey(out []byte, r io.Reader) error {
	_, err := r.Read(out)
	if err != nil {
		return err
	}

	return nil
}
