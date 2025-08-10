# Password Hashing for Go

This package is a simple interface for generating secure password hashes and
verifying them. Its choice of algorithm (Argon2id) and parameters are derived
from what libsodium uses. It also supports peppering, which is similar to a salt
except that the pepper (or "secret") is shared between passwords and not stored
in the database.

If you use this library and set a secret, you should be up to date with OWASP
best practices. **However,**

## Security Warning

**THIS LIBRARY HAS NOT BEEN AUDITED BY A CRYPTOGRAPHER.** I am not a
cryptographer and cannot guarantee the safety of this code. It _looks_ right,
but that's about it. I only wrote this because Go's supplementary cryptography
library does not support peppering or the scrypt-like string format.

I am willing to use this for personal projects but would not be willing to use
this in a vital production application without an independent audit. It also has
very few users (namely, it's only used by me), so there's not that many eyes on
this library. **USE AT YOUR OWN RISK. THIS IS PROVIDED WITHOUT WARRANTY, TO THE
EXTENT PERMITTED BY LAW.**

If you really want this functionality, I recommend supporting the proposal at
https://github.com/golang/go/issues/60740.

## License

This is licensed under the same 3-clause BSD license as Go. See `LICENSE` for
more details.
