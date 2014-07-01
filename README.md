# haskell-nettle

This is the source repository for the "nettle" cabal package, which is a safe binding to the [nettle](http://www.lysator.liu.se/~nisse/nettle/nettle.html) library (tested with 2.7.1, might work with 2.5, does NOT WORK with 3.0).

The binding supports all hash functions, cipher functions, cipher modes and keyed hash functions included in nettle (additionally the AEAD-CCM cipher mode is implemented in pure haskell).

Not included are the PBKDF2 key derivation functions, the public-key algorithms (RSA, DSA, elliptic curves, ECDSA), the pseudo-random generators (lagged Fibonacci and Yarrow), and the base64/base16 encoding/decoding functions.

Also not included are the undocumented ASN1, PGP, PKCS1 and "s-expression" functions.

The haddock generated documentation is available at http://stbuehler.github.io/haskell-nettle/

The test vectors were extracted from the nettle library and ported to haskell; they come from different sources.
