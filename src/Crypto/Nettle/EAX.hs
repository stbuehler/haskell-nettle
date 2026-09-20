{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.EAX
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports the EAX authenticated-encryption with associated-data
(AEAD) construction (Bellare, Rogaway, Wagner; NIST) based on AES-128,
as supported by nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>
-}
module Crypto.Nettle.EAX
    ( -- * EAX

    --
    -- No streaming interface is provided, as this basically violates the
    -- spirit of the "AEAD-should-be-simple-to-use" concept - you only can
    -- use the decrypted data after it got successfully verified.

      eaxAES128Encrypt
    , eaxAES128Decrypt
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Crypto.Nettle.Ciphers.ForeignImports
import Nettle.Utils

{- |
Encrypt plain text and create a verification tag for the encrypted text and some additional data.
@key@ and @nonce@ must not be reused together.
The returned tag is 16 bytes long, but may be shortened for verification (losing security).
-}
eaxAES128Encrypt
    :: B.ByteString
    -- ^ @key@ (must be 16 bytes)
    -> B.ByteString
    -- ^ @nonce@
    -> B.ByteString
    -- ^ @aad@ additional data to be verified
    -> B.ByteString
    -- ^ @plain@ data to encrypt
    -> (B.ByteString, B.ByteString)
    -- ^ returns (@cipher@, @tag@) ciphertext and verification tag
eaxAES128Encrypt key nonce aad plain = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    tag <- B.create 16 (\_ -> return ())
    cipher <- B.create (B.length plain) (\_ -> return ())
    _ <- withByteStringPtr plain $ \psize pptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr cipher $ \_ cipherptr ->
                withByteStringPtr tag $ \_ tagptr ->
                    alignedCtxCreate c_eax_aes128_ctx_size $ \ctxptr ->
                        BA.withByteArray k $ \kptr ->
                            if BA.length k /= 16
                                then error "Invalid key length"
                                else withByteStringPtr nonce $ \noncesize nonceptr -> do
                                    c_eax_aes128_set_key ctxptr kptr
                                    c_eax_aes128_set_nonce ctxptr noncesize nonceptr
                                    c_eax_aes128_update ctxptr aadsize aadptr
                                    c_eax_aes128_encrypt ctxptr psize cipherptr pptr
                                    callNettleHashDigest c_eax_aes128_digest 16 ctxptr tagptr
    return (cipher, tag)

{- |
Decrypt cipher text and verify a (possible shortened) tag for the encrypted text and some additional data.
@key@ and @nonce@ must not be reused together.
-}
eaxAES128Decrypt
    :: B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> Maybe B.ByteString
eaxAES128Decrypt key nonce aad cipher verifytag = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    tag <- B.create 16 (\_ -> return ())
    plain <- B.create (B.length cipher) (\_ -> return ())
    _ <- withByteStringPtr cipher $ \psize pptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr plain $ \_ plainptr ->
                withByteStringPtr tag $ \_ tagptr ->
                    alignedCtxCreate c_eax_aes128_ctx_size $ \ctxptr ->
                        BA.withByteArray k $ \kptr ->
                            if BA.length k /= 16
                                then error "Invalid key length"
                                else withByteStringPtr nonce $ \noncesize nonceptr -> do
                                    c_eax_aes128_set_key ctxptr kptr
                                    c_eax_aes128_set_nonce ctxptr noncesize nonceptr
                                    c_eax_aes128_update ctxptr aadsize aadptr
                                    c_eax_aes128_decrypt ctxptr psize plainptr pptr
                                    callNettleHashDigest c_eax_aes128_digest 16 ctxptr tagptr
    if B.take (B.length verifytag) tag == verifytag
        then return $ Just plain
        else return Nothing
