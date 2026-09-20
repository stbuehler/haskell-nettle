{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

#include <nettle/version.h>

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Module      :  Crypto.Nettle.XOF
Copyright   :  (c) 2026 Clint Adams
License     :  MIT-style (see the file COPYING)

Maintainer  :  clint@debian.org
Stability   :  experimental
Portability :  portable

This module exports extendable-output functions (XOF) supported by nettle:
  <http://www.lysator.liu.se/~nisse/nettle/>
-}
module Crypto.Nettle.XOF
    ( -- * XOF class
      XOF (..)
    , shake
    , shake'

      -- * XOF algorithms
#if (NETTLE_VERSION_MAJOR > 3 || (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 10))
    , SHAKE128
#endif
    , SHAKE256
    ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.Tagged

import Crypto.Nettle.Hash.ForeignImports
import Nettle.Utils

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

{- |
'XOF' is a class for extendable-output functions: like a hash, they absorb a
message, but they can produce an arbitrary number of output bytes.
-}
class XOF a where
    -- | Name of the XOF algorithm
    xofName :: Tagged a String

    -- | Initialize a new context for this XOF algorithm
    xofInit :: a

    -- | Update the context with a bytestring, and return a new context with the updates.
    xofUpdate :: a -> B.ByteString -> a

    -- | Finalize a context and return @outlen@ bytes of output.
    xofFinalize :: a -> Int -> B.ByteString

nettleXOFName :: NettleXOF a => Tagged a String
nettleXOFName = xof_name
nettleXOFInit :: NettleXOF a => a
nettleXOFInit = untagSelf $ do
    size <- xof_ctx_size
    initfun <- xof_init
    return $ xof_Ctx $ BA.unsafeCreate size $ \ctxptr ->
        initfun ctxptr
nettleXOFUpdate :: NettleXOF a => a -> B.ByteString -> a
nettleXOFUpdate c msg = untagSelf $ do
    updatefun <- xof_update
    return $ xof_Ctx $ BA.copyAndFreeze (xof_ctx c) $ \ctxptr ->
        withByteStringPtr msg $ \msglen msgptr ->
            updatefun ctxptr msglen msgptr
nettleXOFFinalize :: NettleXOF a => a -> Int -> B.ByteString
nettleXOFFinalize c outlen = flip witness c $ do
    let ctx = copyScrubbedBytes (xof_ctx c)
    shakefun <- xof_shake
    return $
        unsafeDupablePerformIO $
            B.create outlen $ \outptr ->
                BA.withByteArray ctx $ \ctxptr ->
                    shakefun ctxptr (fromIntegral outlen) outptr

class NettleXOF a where
    xof_ctx_size :: Tagged a Int
    xof_name :: Tagged a String
    xof_init :: Tagged a NettleHashInit
    xof_update :: Tagged a NettleHashUpdate
    xof_shake
        :: Tagged a (Ptr Word8 -> Word -> Ptr Word8 -> IO ())
    xof_ctx :: a -> BA.ScrubbedBytes
    xof_Ctx :: BA.ScrubbedBytes -> a

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------

{- |
Helper to run an XOF over a single (strict) 'B.ByteString', producing @outlen@ bytes.

Example:

> untag (shake (fromString "abc") 64 :: Tagged SHAKE256 B.ByteString)
-}
shake
    :: XOF a
    => B.ByteString
    -- ^ @msg@ argument
    -> Int
    -- ^ @outlen@ argument
    -> Tagged a B.ByteString
shake msg outlen =
    (flip xofFinalize outlen)
        <$> (flip xofUpdate msg <$> tagSelf xofInit)

{- |
Untagged variant of 'shake'; takes a (possible 'undefined') typed 'XOF' context as parameter.

Example:

> shake' (undefined :: SHAKE256) (fromString "abc") 64
-}
shake' :: XOF a => a -> B.ByteString -> Int -> B.ByteString
shake' a msg outlen = shake msg outlen `witness` a

#if (NETTLE_VERSION_MAJOR > 3 || (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 10))
{- | 'SHAKE128' is an extendable-output function based on the Keccak permutation.
  It produces arbitrary-length output with a security strength of 128 bits.
  It is only available with Nettle >= 3.10.
-}
data SHAKE128 = SHAKE128 {shake128_ctx :: BA.ScrubbedBytes}

instance NettleXOF SHAKE128 where
    xof_ctx_size = Tagged c_sha3_128_ctx_size
    xof_name = Tagged "SHAKE128"
    xof_init = Tagged c_sha3_128_init
    xof_update = Tagged c_sha3_128_update
    xof_shake = Tagged c_sha3_128_shake
    xof_ctx = shake128_ctx
    xof_Ctx = SHAKE128

instance XOF SHAKE128 where
    xofName     = nettleXOFName
    xofInit     = nettleXOFInit
    xofUpdate   = nettleXOFUpdate
    xofFinalize = nettleXOFFinalize
#endif

{- | 'SHAKE256' is an extendable-output function based on the Keccak permutation.
  It produces arbitrary-length output with a security strength of 256 bits.
-}
data SHAKE256 = SHAKE256 {shake256_ctx :: BA.ScrubbedBytes}

instance NettleXOF SHAKE256 where
    xof_ctx_size = Tagged c_sha3_256_ctx_size
    xof_name = Tagged "SHAKE256"
    xof_init = Tagged c_sha3_256_init
    xof_update = Tagged c_sha3_256_update
    xof_shake = Tagged c_sha3_256_shake
    xof_ctx = shake256_ctx
    xof_Ctx = SHAKE256

instance XOF SHAKE256 where
    xofName     = nettleXOFName
    xofInit     = nettleXOFInit
    xofUpdate   = nettleXOFUpdate
    xofFinalize = nettleXOFFinalize
