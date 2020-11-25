package encryption

type (
	SecretKeyEncryption string
	PublicKeyEncryption string
)

const (
	ChaCha20Poly1305 SecretKeyEncryption = "chacha20poly1305"

	XSalsa20 PublicKeyEncryption = "xsalsa20"
)

func ValidateSecretKeyEnum(value SecretKeyEncryption) (SecretKeyEncryption, error) {
	switch casted := value; casted {
	case ChaCha20Poly1305:
		return casted, nil
	}

	return "", ErrAlgorithmNotSupported
}

func ValidatePublicKeyEnum(value PublicKeyEncryption) (PublicKeyEncryption, error) {
	switch value {
	case XSalsa20:
		return value, nil
	}

	return "", ErrAlgorithmNotSupported
}

func (s *SecretKeyEncryption) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	*s, err = ValidateSecretKeyEnum(SecretKeyEncryption(v))

	return err
}

func (s *SecretKeyEncryption) UnmarshalJSON(bytes []byte) (err error) {
	*s, err = ValidateSecretKeyEnum(SecretKeyEncryption(bytes))
	return err
}

func (s SecretKeyEncryption) MarshalYAML() (interface{}, error) {
	return string(s), nil
}

func (s SecretKeyEncryption) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}

func (s *PublicKeyEncryption) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	*s, err = ValidatePublicKeyEnum(PublicKeyEncryption(v))
	return err
}

func (s *PublicKeyEncryption) UnmarshalJSON(bytes []byte) (err error) {
	*s, err = ValidatePublicKeyEnum(PublicKeyEncryption(bytes))
	return err
}

func (s PublicKeyEncryption) MarshalYAML() (interface{}, error) {
	return string(s), nil
}

func (s PublicKeyEncryption) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}
