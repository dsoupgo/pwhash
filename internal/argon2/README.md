# Modified golang.org/x/crypto/argon2

This is a modified version of Go's supplementary cryptography library's Argon2
implementation.

It has been slightly modified to add `IDKeyWithSecret`, which allows us to
specify the secret parameter to the internal `deriveKey` function.

If/when Go adds an equivalent function, this can be eliminated from this
repository.

Existing code is not changed and should be kept up to date with what you can
find at https://github.com/golang/crypto/tree/master/argon2. The newly added
function is kept in `pwhash.go` in this directory.
