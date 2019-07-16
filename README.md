# pwcrypto

> Go library with password cryptography routines

[![Build Status](https://travis-ci.org/rubenv/pwcrypto.svg?branch=master)](https://travis-ci.org/rubenv/pwcrypto) [![GoDoc](https://godoc.org/github.com/rubenv/pwcrypto?status.png)](https://godoc.org/github.com/rubenv/pwcrypto)

This library provides routines for securly storing passwords in a database and validating them.

Features:

* All passwords stored with one-way hashes
* Unique salts per user
* Upgradable cryptography algorithms and hash strengths
* Indicates when passwords should be rehashed to gradually upgrade password cryptography
* Configurable hashing routines

## Usage

Create a `Crypto` object, which will hold the cryptography routines used. Pass
the algorithms you wish to use as arguments. The first algorithm will be used
for storing passwords, the other algorithms are accepted for existing passwords
(see `Password Upgrades` below).

```
passwords := pwcrypto.New(
    NewScryptCrypto(),
    NewPBKDF2Crypto(),
    NewSHA256Crypto(),
)
```

Use `Hash()` when storing a password for a user:

```
hash, err := passwords.Hash("mySecurePassword")
```

The value of `hash` is a string containing the hashed password and a set of
configuration parameters used for verifying the password. Store this string in
your database.

Use `Check()` for validating passwords:

```
valid, mustUpgrade, err := passwords.Check("someUserInput", hash)
```

In the above:

* `hash` is the value you previously stored in your database, look it up for the user trying to authenticate
* `"someUserInput"` is the password entered during login
* `valid` indicates whether the input is correct
* `mustUpgrade` indicates that the password needs to be upgraded (see below).

## Password Upgrades

During check, `mustUpgrade` will be `true` if the database hash uses an
outdated hash. In this case you should use `Hash()` again with the user input
and store the new hashed value in your database.

This allows you to to upgrade your database gradually. Suppose you previously
used `SHA1`, but want to upgrade to `SHA256`. Just configure pwcrypto with
`SHA256` as the primary algorithm and `SHA1` as the fallback algorithm.

```
passwords := pwcrypto.New(
    NewSHA256Crypto(),
    NewSHA1Crypto(),
)
```

Whenever a user logs in correctly, you'll receive `mustUpgrade == true`. At
this point you can use the user input to re-hash the password, which will then
use `SHA256`.

## Configuring hashing algorithms

By default, the unparametrized algorithm constructor will return a
best-practices version of the algorithm.

You can use the more verbose constructor to override specific options (if any).

### PBKDF2

Default: `NewPBKDF2Crypto()`
Verbose: `NewPBKDF2CryptoWithOptions(iter, keyLen, saltLen int, hashFns []HashFunction)`

Allows you to override the number of iterations, key length, salt length and
hashing functions (for HMAC). Similar to crypto algorithms, the first hash
function is preferred, others are for fallback compatibility.

### Scrypt

Default: NewScryptCrypto()
Verbose: NewScryptCryptoWithOptions(saltLen, cpuMemCost, r, p, keyLen int)

## License

This library is distributed under the [MIT](LICENSE) license.
