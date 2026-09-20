{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.Poly1305
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports the Poly1305-AES message authentication code supported
by nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>

Poly1305-AES is the (deprecated) original construction by D. J. Bernstein,
where the one-time pad is generated with AES from a nonce.  The modern
Poly1305 construction used by ChaCha-Poly1305 (RFC 7539) is available via
'Crypto.Nettle.ChaChaPoly1305'.
-}
module Crypto.Nettle.Poly1305
    ( -- * Poly1305-AES
      poly1305AES
    , poly1305AESInit
    , poly1305AESUpdate
    , poly1305AESFinalize
    , Poly1305AES
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Crypto.Nettle.Hash.ForeignImports
import Nettle.Utils

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

-- | Incremental state of a Poly1305-AES MAC computation.
newtype Poly1305AES = Poly1305AES AlignedContext

poly1305aesInit
    :: B.ByteString
    -- ^ @key@ (32 bytes: 16 byte \"r\", 16 byte \"s\")
    -> Poly1305AES
poly1305aesInit key = Poly1305AES $
    unsafeDupablePerformIO $
        alignedCtxCreate c_poly1305_aes_ctx_size $ \ctxptr ->
            BA.withByteArray key $ \keyptr ->
                if BA.length key /= 32
                    then error "Invalid key length"
                    else
                        c_poly1305_aes_set_key ctxptr keyptr

poly1305aesSetNonce :: Poly1305AES -> B.ByteString -> Poly1305AES
poly1305aesSetNonce (Poly1305AES c) nonce = Poly1305AES $
    unsafeDupablePerformIO $
        alignedCtxCopy c c_poly1305_aes_ctx_size $ \ctxptr ->
            BA.withByteArray nonce $ \nonceptr ->
                if BA.length nonce /= 16
                    then error "Invalid nonce length"
                    else
                        c_poly1305_aes_set_nonce ctxptr nonceptr

poly1305aesUpdate :: Poly1305AES -> B.ByteString -> Poly1305AES
poly1305aesUpdate (Poly1305AES c) msg = Poly1305AES $
    unsafeDupablePerformIO $
        alignedCtxCopy c c_poly1305_aes_ctx_size $ \ctxptr ->
            withByteStringPtr msg $ \msglen msgptr ->
                c_poly1305_aes_update ctxptr msglen msgptr

poly1305aesFinalize :: Poly1305AES -> B.ByteString
poly1305aesFinalize (Poly1305AES c) = unsafeDupablePerformIO $
    B.create c_poly1305_aes_digest_size $ \digestptr ->
        BA.withByteArray (alignedCtxBuffer c) $ \ctxptr ->
            callNettleHashDigest
                c_poly1305_aes_digest
                c_poly1305_aes_digest_size
                (ctxptr `plusPtr` alignedCtxOffset c)
                digestptr

{- |
Initialize a Poly1305-AES MAC computation with a @key@ (32 bytes) and @nonce@ (16 bytes).
-}
poly1305AESInit :: B.ByteString -> B.ByteString -> Poly1305AES
poly1305AESInit key nonce = poly1305aesSetNonce (poly1305aesInit key) nonce

{- |
Add more message data to a Poly1305-AES MAC computation.
-}
poly1305AESUpdate :: Poly1305AES -> B.ByteString -> Poly1305AES
poly1305AESUpdate = poly1305aesUpdate

{- |
Produce the final 16 byte (128 bit) tag of a Poly1305-AES MAC computation.
-}
poly1305AESFinalize :: Poly1305AES -> B.ByteString
poly1305AESFinalize = poly1305aesFinalize

{- |
One-shot Poly1305-AES MAC: calculate the 16 byte tag for a @key@ (32 bytes),
@nonce@ (16 bytes) and @msg@.
-}
poly1305AES
    :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString
poly1305AES key nonce msg =
    poly1305aesFinalize $
        poly1305aesUpdate
            (poly1305aesSetNonce (poly1305aesInit key) nonce)
            msg
