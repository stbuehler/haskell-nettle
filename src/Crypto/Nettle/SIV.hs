{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.SIV
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports the SIV authenticated-encryption with associated-data
(AEAD) construction (RFC 5297, AES-SIV) based on AES-CMAC, as supported by
nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>
-}
module Crypto.Nettle.SIV
    ( -- * SIV

    --
    -- No streaming interface is provided, as this basically violates the
    -- spirit of the "AEAD-should-be-simple-to-use" concept - you only can
    -- use the decrypted data after it got successfully verified.

      sivAES128Encrypt
    , sivAES128Decrypt
    , sivAES256Encrypt
    , sivAES256Decrypt
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Foreign.C.Types (CInt)

import Crypto.Nettle.Ciphers.ForeignImports
import Nettle.Utils

{- |
Encrypt plain text and create a verification tag for the encrypted text and some additional data.
SIV is deterministic: the @nonce@ is used only as additional data, and is not required to be unique.
The returned tag is 16 bytes long, but may be shortened for verification (losing security).
-}
sivAES128Encrypt
    :: B.ByteString
    -- ^ @key@ (must be 32 bytes)
    -> B.ByteString
    -- ^ @nonce@ (must not be empty)
    -> B.ByteString
    -- ^ @aad@ additional data to be verified
    -> B.ByteString
    -- ^ @plain@ data to encrypt
    -> (B.ByteString, B.ByteString)
    -- ^ returns (@cipher@, @tag@) ciphertext and verification tag
sivAES128Encrypt =
    sivEncrypt
        c_siv_cmac_aes128_ctx_size
        c_siv_cmac_aes128_set_key
        c_siv_cmac_aes128_encrypt_message
        32

{- |
Decrypt cipher text and verify a (possible shortened) tag for the encrypted text and some additional data.
-}
sivAES128Decrypt
    :: B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> Maybe B.ByteString
sivAES128Decrypt =
    sivDecrypt
        c_siv_cmac_aes128_ctx_size
        c_siv_cmac_aes128_set_key
        c_siv_cmac_aes128_decrypt_message
        32

{- |
Encrypt plain text and create a verification tag for the encrypted text and some additional data.
SIV is deterministic: the @nonce@ is used only as additional data, and is not required to be unique.
The returned tag is 16 bytes long, but may be shortened for verification (losing security).
-}
sivAES256Encrypt
    :: B.ByteString
    -- ^ @key@ (must be 64 bytes)
    -> B.ByteString
    -- ^ @nonce@ (must not be empty)
    -> B.ByteString
    -- ^ @aad@ additional data to be verified
    -> B.ByteString
    -- ^ @plain@ data to encrypt
    -> (B.ByteString, B.ByteString)
    -- ^ returns (@cipher@, @tag@) ciphertext and verification tag
sivAES256Encrypt =
    sivEncrypt
        c_siv_cmac_aes256_ctx_size
        c_siv_cmac_aes256_set_key
        c_siv_cmac_aes256_encrypt_message
        64

{- |
Decrypt cipher text and verify a (possible shortened) tag for the encrypted text and some additional data.
-}
sivAES256Decrypt
    :: B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> Maybe B.ByteString
sivAES256Decrypt =
    sivDecrypt
        c_siv_cmac_aes256_ctx_size
        c_siv_cmac_aes256_set_key
        c_siv_cmac_aes256_decrypt_message
        64

sivEncrypt
    :: Int
    -> (Ptr Word8 -> Ptr Word8 -> IO ())
    -> ( Ptr Word8
         -> Word
         -> Ptr Word8
         -> Word
         -> Ptr Word8
         -> Word
         -> Ptr Word8
         -> Ptr Word8
         -> IO ()
       )
    -> Int
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> (B.ByteString, B.ByteString)
sivEncrypt ctxsize setkey encmsg keysize key nonce aad plain = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    let clength = B.length plain + 16
    out <- B.create clength (\_ -> return ())
    _ <- withByteStringPtr plain $ \_ pptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr nonce $ \noncesize nonceptr ->
                withByteStringPtr out $ \_ outptr ->
                    withAlignedContext ctxsize $ \ctxptr ->
                        BA.withByteArray k $ \kptr ->
                            if BA.length k /= keysize
                                then error "Invalid key length"
                                else
                                    if noncesize == 0
                                        then error "Invalid nonce length"
                                        else do
                                            setkey ctxptr kptr
                                            encmsg
                                                ctxptr
                                                noncesize
                                                nonceptr
                                                aadsize
                                                aadptr
                                                (fromIntegral clength)
                                                outptr
                                                pptr
    return (B.drop 16 out, B.take 16 out)

sivDecrypt
    :: Int
    -> (Ptr Word8 -> Ptr Word8 -> IO ())
    -> ( Ptr Word8
         -> Word
         -> Ptr Word8
         -> Word
         -> Ptr Word8
         -> Word
         -> Ptr Word8
         -> Ptr Word8
         -> IO CInt
       )
    -> Int
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> B.ByteString
    -> Maybe B.ByteString
sivDecrypt ctxsize setkey decmsg keysize key nonce aad cipher verifytag = unsafeDupablePerformIO $ do
    let k = copyAndConvertToScrubbedBytes key
    let src = verifytag `B.append` cipher
    plain <- B.create (B.length cipher) (\_ -> return ())
    ok <- withByteStringPtr src $ \_ srcptr ->
        withByteStringPtr aad $ \aadsize aadptr ->
            withByteStringPtr nonce $ \noncesize nonceptr ->
                withByteStringPtr plain $ \_ plainptr ->
                    withAlignedContext ctxsize $ \ctxptr ->
                        BA.withByteArray k $ \kptr ->
                            if BA.length k /= keysize
                                then error "Invalid key length"
                                else
                                    if noncesize == 0
                                        then error "Invalid nonce length"
                                        else do
                                            setkey ctxptr kptr
                                            decmsg
                                                ctxptr
                                                noncesize
                                                nonceptr
                                                aadsize
                                                aadptr
                                                (fromIntegral (B.length cipher))
                                                plainptr
                                                srcptr
    if ok /= 0 then return $ Just plain else return Nothing
