// Package pwhash generates and compares password hashes.
package pwhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"

	"github.com/dsoupgo/pwhash/internal/argon2"
)

// ErrPasswordMismatch is returned when the password does not match the hash.
var ErrPasswordMismatch = errors.New("passwords does not match hash")

// ErrInvalidHash is returned when the password hash is malformed.
var ErrInvalidHash = errors.New("password hash is malformed")

// Hasher defines parameters for hashing and verifying passwords.
type Hasher struct {
	// Prevent fragile positional arguments.
	_ struct{}

	// Secret key used when generating passwords. This is optional, but when
	// it is used, it's called "peppering".
	Secret []byte
}

// Hash hashes the given password and returns it.
func (h Hasher) Hash(password string) string {
	// These defaults are ripped from libsodium's interactive settings.
	// They are above OWASP recommendations.
	const (
		saltLen = 16
		time    = 2
		memory  = 64 * 1024
		threads = 1
		keyLen  = 32
	)

	var salt [saltLen]byte

	// Go guarantees that this never returns an error. We check anyway, but
	// panic since it should never ever happen.
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}

	hash := argon2.IDKeyWithSecret([]byte(password), salt[:], h.Secret, time, memory, threads, keyLen)

	salt64 := base64.RawStdEncoding.EncodeToString(salt[:])
	hash64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%v,t=%v,p=%v$%v$%v", memory, time, threads, salt64, hash64)
}

// Verify returns true if password and encodedHash match.
//
// If the passwords match, this returns nil. Otherwise, it returns an error
// indicating whether this was caused by password mismatch or by a malformed
// hash.
//
// It may be helpful to log the reason for error whenever it is not
// ErrPasswordMismatch, since this may indicate database integrity errors, etc.
func (h Hasher) Verify(passhash, password string) error {
	memory, time, threads, salt, hash, err := decodeHash(passhash)
	if err != nil {
		return err
	}

	hashLen := len(hash)

	if hashLen > math.MaxUint32 {
		return fmt.Errorf("%w: hash length too long", ErrInvalidHash)
	}

	hash2 := argon2.IDKeyWithSecret([]byte(password), salt, h.Secret, time, memory, threads, uint32(hashLen))

	if subtle.ConstantTimeCompare(hash, hash2) == 1 {
		return nil
	}

	return ErrPasswordMismatch
}

var reHash = regexp.MustCompile(`\A\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)\z`)

func decodeHash(passhash string) (uint32, uint32, uint8, []byte, []byte, error) {
	match := reHash.FindStringSubmatch(passhash)
	if match == nil {
		return 0, 0, 0, nil, nil, ErrInvalidHash
	}

	memory, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("%w near memory: %w", ErrInvalidHash, err)
	}

	time, err := strconv.ParseUint(match[2], 10, 32)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("%w near time: %w", ErrInvalidHash, err)
	}

	threads, err := strconv.ParseUint(match[3], 10, 8)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("%w near threads: %w", ErrInvalidHash, err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(match[4])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("%w near salt: %w", ErrInvalidHash, err)
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(match[5])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("%w near salt: %w", ErrInvalidHash, err)
	}

	return uint32(memory), uint32(time), uint8(threads), salt, hash, nil
}
