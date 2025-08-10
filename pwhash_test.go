package pwhash_test

import (
	"encoding/base64"
	"testing"

	"github.com/dsoupgo/pwhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	t.Parallel()

	hasher := pwhash.Hasher{Secret: nil}

	err := hasher.Verify(hasher.Hash("dragon"), "dragon")
	require.NoError(t, err)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	hasher := pwhash.Hasher{Secret: nil}

	err := hasher.Verify(
		"$argon2id$v=19$m=19456,t=2,p=1$RlVPRU1KMlEyUTRMWElYTEpCU0NPM01aNVI$PkMb+r2gXF9govQQvhgbDJ9h0l4h1XrRJL0PMRcm8qk",
		"dragon",
	)
	require.NoError(t, err)

	err = hasher.Verify(
		"$argon2id$v=19$m=19456,t=2,p=1$RlVPRU1KMlEyUTRMWElYTEpCU0NPM01aNVI$PkMb+r2gXF9govQQvhgbDJ9h0l4h1XrRJL0PMRcm8qk",
		"dragoN",
	)
	require.ErrorIs(t, err, pwhash.ErrPasswordMismatch)

	err = hasher.Verify(
		"$argon2id$v=19$m=19456,t=2,p=X$RlVPRU1KMlEyUTRMWElYTEpCU0NPM01aNVI$PkMb+r2gXF9govQQvhgbDJ9h0l4h1XrRJL0PMRcm8qk",
		"dragoN",
	)
	require.ErrorIs(t, err, pwhash.ErrInvalidHash)
}

func TestSecret(t *testing.T) {
	t.Parallel()

	hasher := pwhash.Hasher{
		Secret: []byte{
			38, 55, 130, 162, 35, 209, 201, 24, 72, 236, 132, 132,
			50, 108, 43, 187, 153, 201, 146, 156, 135, 248, 173, 61,
			229, 34, 137, 74, 48, 227, 22, 88,
		},
	}

	// Ensure we can't verify something that didn't use the secret.
	err := hasher.Verify(
		"$argon2id$v=19$m=19456,t=2,p=1$RlVPRU1KMlEyUTRMWElYTEpCU0NPM01aNVI$PkMb+r2gXF9govQQvhgbDJ9h0l4h1XrRJL0PMRcm8qk",
		"dragon",
	)
	require.ErrorIs(t, err, pwhash.ErrPasswordMismatch)

	// Ensure that verifying something we generated still works.
	hash := hasher.Hash("dragon")
	err = hasher.Verify(hash, "dragon")
	require.NoError(t, err)

	// Ensure that secret does not appear in the string, either as raw bytes
	// or as base64.
	assert.NotContains(t, hash, string(hasher.Secret))
	assert.NotContains(t, hash, base64.RawStdEncoding.EncodeToString(hasher.Secret))
}
