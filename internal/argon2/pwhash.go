package argon2

// IDKeyWithSecret is equivalent to IDKey except that it accepts a secret.
func IDKeyWithSecret(password, salt, secret []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2id, password, salt, secret, nil, time, memory, threads, keyLen)
}
