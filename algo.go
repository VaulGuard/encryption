package encryption

type (
	SecretKeyEncryption string
	PublicKeyEncryption string
)

const (
	ChaCha20Poly1305 SecretKeyEncryption = "chacha20poly1305"

	XSalsa20 PublicKeyEncryption = "xsalsa20"
)

func (s *SecretKeyEncryption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}

	switch casted := SecretKeyEncryption(v); casted {
	case ChaCha20Poly1305:
		*s = casted
		return nil
	}

	return ErrAlgorithmNotSupported
}

func (s *SecretKeyEncryption) UnmarshalJSON(bytes []byte) error {
	switch casted := SecretKeyEncryption(bytes); casted {
	case ChaCha20Poly1305:
		*s = casted
		return nil
	}
	return ErrAlgorithmNotSupported
}

func (s SecretKeyEncryption) MarshalYAML() (interface{}, error) {
	return string(s), nil
}

func (s SecretKeyEncryption) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}

func (s *PublicKeyEncryption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}

	switch casted := PublicKeyEncryption(v); casted {
	case XSalsa20:
		*s = casted
		return nil
	}

	return ErrAlgorithmNotSupported
}

func (s *PublicKeyEncryption) UnmarshalJSON(bytes []byte) error {
	switch casted := PublicKeyEncryption(bytes); casted {
	case XSalsa20:
		*s = casted
		return nil
	}

	return ErrAlgorithmNotSupported
}

func (s PublicKeyEncryption) MarshalYAML() (interface{}, error) {
	return string(s), nil
}

func (s PublicKeyEncryption) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}
