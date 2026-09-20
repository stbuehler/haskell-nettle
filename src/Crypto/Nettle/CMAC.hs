{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.CMAC
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports CMAC (Cipher-based Message Authentication Code,
NIST SP 800-38B) algorithms supported by nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>
-}
module Crypto.Nettle.CMAC
    ( -- * CMAC algorithms
      CMAC_AES128
    , CMAC_AES256
    , CMAC_DES3
    , cmacInit
    , cmacInit'
    , cmac
    , cmac'
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.Tagged

import Crypto.Nettle.Hash.ForeignImports
import Crypto.Nettle.Hash.Types
import Nettle.Utils

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

class NettleCMAC a where
    cmac_ctx_size :: Tagged a Int
    cmac_digest_size :: Tagged a Int
    cmac_name :: Tagged a String
    cmac_set_key :: Tagged a (Ptr Word8 -> Ptr Word8 -> IO ())
    cmac_update
        :: Tagged a (Ptr Word8 -> Word -> Ptr Word8 -> IO ())
    cmac_digest :: Tagged a NettleHashDigest
    cmac_ctx :: a -> AlignedContext
    cmac_Ctx :: AlignedContext -> a

nettleCMACInit :: NettleCMAC a => B.ByteString -> a
nettleCMACInit key = untagSelf $ do
    size <- cmac_ctx_size
    setkey <- cmac_set_key
    return $
        cmac_Ctx $
            unsafeDupablePerformIO $
                alignedCtxCreate size $ \ctxptr ->
                    BA.withByteArray key $ \keyptr ->
                        setkey ctxptr keyptr
nettleCMACUpdate :: NettleCMAC a => a -> B.ByteString -> a
nettleCMACUpdate c msg = untagSelf $ do
    size <- cmac_ctx_size
    updatefun <- cmac_update
    return $
        cmac_Ctx $
            unsafeDupablePerformIO $
                alignedCtxCopy (cmac_ctx c) size $ \ctxptr ->
                    withByteStringPtr msg $ \msglen msgptr ->
                        updatefun ctxptr msglen msgptr
nettleCMACFinalize :: NettleCMAC a => a -> B.ByteString
nettleCMACFinalize c = flip witness c $ do
    let ctx = cmac_ctx c
    digestSize <- cmac_digest_size
    digestfun <- cmac_digest
    return $
        unsafeDupablePerformIO $
            B.create digestSize $ \digestptr ->
                BA.withByteArray (alignedCtxBuffer ctx) $ \ctxptr ->
                    callNettleHashDigest
                        digestfun
                        digestSize
                        (ctxptr `plusPtr` alignedCtxOffset ctx)
                        digestptr

#define INSTANCE_CMAC(Typ) \
instance NettleCMAC Typ => KeyedHashAlgorithm Typ where \
	{ implKeyedHashDigestSize = cmac_digest_size \
	; implKeyedHashName       = cmac_name \
	; implKeyedHashInit       = nettleCMACInit \
	; implKeyedHashUpdate     = nettleCMACUpdate \
	; implKeyedHashFinalize   = nettleCMACFinalize \
	}

-- | 'CMAC_AES128' is the CMAC algorithm based on AES-128 (NIST SP 800-38B), with a 16 byte (128 bit) key.
data CMAC_AES128 = CMAC_AES128 {cmac_aes128_ctx :: AlignedContext}

instance NettleCMAC CMAC_AES128 where
    cmac_ctx_size = Tagged c_cmac_aes128_ctx_size
    cmac_digest_size = Tagged 16
    cmac_name = Tagged "CMAC-AES128"
    cmac_set_key = Tagged c_cmac_aes128_set_key
    cmac_update = Tagged c_cmac_aes128_update
    cmac_digest = Tagged c_cmac_aes128_digest
    cmac_ctx = cmac_aes128_ctx
    cmac_Ctx = CMAC_AES128
INSTANCE_CMAC (CMAC_AES128)

-- | 'CMAC_AES256' is the CMAC algorithm based on AES-256 (NIST SP 800-38B), with a 32 byte (256 bit) key.
data CMAC_AES256 = CMAC_AES256 {cmac_aes256_ctx :: AlignedContext}

instance NettleCMAC CMAC_AES256 where
    cmac_ctx_size = Tagged c_cmac_aes256_ctx_size
    cmac_digest_size = Tagged 16
    cmac_name = Tagged "CMAC-AES256"
    cmac_set_key = Tagged c_cmac_aes256_set_key
    cmac_update = Tagged c_cmac_aes256_update
    cmac_digest = Tagged c_cmac_aes256_digest
    cmac_ctx = cmac_aes256_ctx
    cmac_Ctx = CMAC_AES256
INSTANCE_CMAC (CMAC_AES256)

-- | 'CMAC_DES3' is the CMAC algorithm based on 3DES (NIST SP 800-38B), with a 24 byte (192 bit) key.
data CMAC_DES3 = CMAC_DES3 {cmac_des3_ctx :: AlignedContext}

instance NettleCMAC CMAC_DES3 where
    cmac_ctx_size = Tagged c_cmac_des3_ctx_size
    cmac_digest_size = Tagged 8
    cmac_name = Tagged "CMAC-DES3"
    cmac_set_key = Tagged c_cmac_des3_set_key
    cmac_update = Tagged c_cmac_des3_update
    cmac_digest = Tagged c_cmac_des3_digest
    cmac_ctx = cmac_des3_ctx
    cmac_Ctx = CMAC_DES3
INSTANCE_CMAC (CMAC_DES3)

{- |
'cmacInit' initializes a 'KeyedHash' to calculate the CMAC for a message with the given @key@.
-}
cmacInit
    :: KeyedHashAlgorithm a
    => B.ByteString
    -- ^ @key@ argument
    -> Tagged a KeyedHash
cmacInit = keyedHashInit

{- |
Untagged variant of 'cmacInit'; takes a (possible 'undefined') typed 'CMAC' context as parameter.
-}
cmacInit'
    :: KeyedHashAlgorithm a => a -> B.ByteString -> KeyedHash
cmacInit' a key = cmacInit key `witness` a

{- |
Calculate the CMAC for a @key@ and @message@.
-}
cmac
    :: KeyedHashAlgorithm a
    => B.ByteString
    -- ^ @key@ argument
    -> B.ByteString
    -- ^ @message@ argument
    -> Tagged a B.ByteString
cmac = keyedHash

{- |
Untagged variant of 'cmac'; takes a (possible 'undefined') typed 'CMAC' context as parameter.
-}
cmac'
    :: KeyedHashAlgorithm a
    => a -> B.ByteString -> B.ByteString -> B.ByteString
cmac' a key msg = cmac key msg `witness` a
