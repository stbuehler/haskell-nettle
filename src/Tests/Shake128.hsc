{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

#include <nettle/version.h>

#if (NETTLE_VERSION_MAJOR > 3 || (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 10))
module Shake128 (shake128Tests) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Crypto.Nettle.XOF
import TestUtils

shake128Vectors :: [(B.ByteString, String, Int)]
shake128Vectors =
    [ ("", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", 32)
    , ("abc", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8", 32)
    , ("abc", "5881092dd818bf5cf8a3ddb793fbcba7", 16)
    ]

testShake128 :: Tagged SHAKE128 Test
testShake128 = do
    results <- mapM assertShake shake128Vectors
    return $ testCases "testing XOF SHAKE128" results
  where
    assertShake (src, out, outlen) = do
        h' <- shake src outlen
        return $ assertEqualHex "" (hs out) h'

testIncremental128 :: Tagged SHAKE128 Test
testIncremental128 = do
    let msg = BC.pack "abcdefghijklmnopqrstuvwxyz"
    one <- shake msg 64
    let c1 = xofUpdate (xofInit :: SHAKE128) (B.take 3 msg)
        c2 = xofUpdate c1 (B.drop 3 (B.take 11 msg))
        c3 = xofUpdate c2 (B.drop 11 msg)
        multi = xofFinalize c3 64
    return $
        testCase "incremental SHAKE128 output equals one-shot" $
            assertEqual "incremental SHAKE128" one multi

shake128Tests :: [Test]
shake128Tests =
    [ testShake128 `witness` (undefined :: SHAKE128)
    , testIncremental128 `witness` (undefined :: SHAKE128)
    ]
#else
module Shake128 (shake128Tests) where

import TestUtils

shake128Tests :: [Test]
shake128Tests = []
#endif
