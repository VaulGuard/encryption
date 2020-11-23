package encryption

type KeyGenerator interface {
	// Generate method generates appropriate key for the implementing algorithm
	// out parameter allows the unencrypted value to be used further in the application
	Generate(out ...interface{}) error
}
