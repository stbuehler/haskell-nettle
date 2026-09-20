{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.OCB
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports the OCB authenticated-encryption with associated-data
(AEAD) construction (Rogaway, "Efficient Authenticated Encryption with
Associated Data") based on AES-128, as supported by nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>

The one-shot @ocb_aes128_decrypt_message@ function in Nettle 4.0 is broken
(it passes the address of the decryption context instead of the context
itself, breaking messages of 16 bytes or larger); the streaming primitives
are used instead, which work on all supported Nettle versions.
-}
module Crypto.Nettle.OCB
    ( -- * OCB

    --
    -- No streaming interface is provided, as this basically violates the
    -- spirit of the "AEAD-should-be-simple-to-use" concept - you only can
    -- use the decrypted data after it got successfully verified.

      ocbAES128Encrypt
    , ocbAES128Decrypt
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Crypto.Nettle.Ciphers.ForeignImports
import Nettle.Utils

{- |
Encrypt plain text and create a verification tag for the encrypted text and some additional data.
@key@ and @nonce@ must not be reused together.  @nonce@ must not be longer than 15 bytes.
The returned tag is 16 bytes long, but may be shortened for verification (losing security).
-}
ocbAES128Encrypt
    :: B.ByteString
    -- ^ @key@ (must be 16 bytes)
    -> B.ByteString
    -- ^ @nonce@ (must not be longer than 15 bytes)
    -> B.ByteString
    -- ^ @aad@ additional data to be verified
    -> B.ByteString
    -- ^ @plain@ data to encrypt
    -> (B.ByteString, B.ByteString)
    -- ^ returns (@cipher@, @tag@) ciphertext and verification tag
ocbAES128Encrypt key nonce aad plain = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    cipher <- B.create (B.length plain) (\_ -> return ())
    tag <- B.create 16 (\_ -> return ())
    _ <- withByteStringPtr plain $ \psize pptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr nonce $ \noncesize nonceptr ->
                withByteStringPtr cipher $ \_ cipherptr ->
                    withByteStringPtr tag $ \_ tagptr ->
                        withAlignedContext c_ocb_aes128_key_ctx_size $ \keyctxptr ->
                            withAlignedContext c_ocb_aes128_ctx_size $ \ctxptr ->
                                BA.withByteArray k $ \kptr ->
                                    if BA.length k /= 16
                                        then error "Invalid key length"
                                        else
                                            if noncesize > 15
                                                then error "Invalid nonce length"
                                                else do
                                                    c_ocb_aes128_set_encrypt_key keyctxptr kptr
                                                    c_ocb_aes128_set_nonce ctxptr keyctxptr 16 noncesize nonceptr
                                                    c_ocb_aes128_update ctxptr keyctxptr aadsize aadptr
                                                    c_ocb_aes128_encrypt ctxptr keyctxptr psize cipherptr pptr
                                                    callNettleOcbDigest
                                                        c_ocb_aes128_digest
                                                        16
                                                        ctxptr
                                                        keyctxptr
                                                        tagptr
    return (cipher, tag)

{- |
Decrypt cipher text and verify a (possible shortened) tag for the encrypted text and some additional data.
@key@ and @nonce@ must not be reused together.
-}
ocbAES128Decrypt
    :: B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> Maybe B.ByteString
ocbAES128Decrypt key nonce aad cipher verifytag = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    plain <- B.create (B.length cipher) (\_ -> return ())
    tag <- B.create 16 (\_ -> return ())
    _ <- withByteStringPtr cipher $ \psize pptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr nonce $ \noncesize nonceptr ->
                withByteStringPtr plain $ \_ plainptr ->
                    withByteStringPtr tag $ \_ tagptr ->
                        withAlignedContext c_ocb_aes128_key_ctx_size $ \keyctxptr ->
                            withAlignedContext c_aes128_ctx_size $ \decryptptr ->
                                withAlignedContext c_ocb_aes128_ctx_size $ \ctxptr ->
                                    BA.withByteArray k $ \kptr ->
                                        if BA.length k /= 16
                                            then error "Invalid key length"
                                            else
                                                if noncesize > 15
                                                    then error "Invalid nonce length"
                                                    else do
                                                        c_ocb_aes128_set_decrypt_key keyctxptr decryptptr kptr
                                                        c_ocb_aes128_set_nonce ctxptr keyctxptr 16 noncesize nonceptr
                                                        c_ocb_aes128_update ctxptr keyctxptr aadsize aadptr
                                                        c_ocb_aes128_decrypt
                                                            ctxptr
                                                            keyctxptr
                                                            decryptptr
                                                            psize
                                                            plainptr
                                                            pptr
                                                        callNettleOcbDigest
                                                            c_ocb_aes128_digest
                                                            16
                                                            ctxptr
                                                            keyctxptr
                                                            tagptr
    if B.take (B.length verifytag) tag == verifytag
        then return $ Just plain
        else return Nothing
