{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Crypto.Nettle.XOF
import TestUtils

assertShake
    :: XOF a => (B.ByteString, String, Int) -> Tagged a Assertion
assertShake (src, out, outlen) = do
    h' <- shake src outlen
    return $ assertEqualHex "" (hs out) h'

testShake :: XOF a => Tagged a Test
testShake = do
    name <- xofName
    results <- mapM assertShake (xofTestVectors name)
    return $ testCases ("testing XOF " ++ name) results

xofTestVectors :: String -> [(B.ByteString, String, Int)]
xofTestVectors "SHAKE128" =
    [
        ( ""
        , "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        , 32
        )
    ,
        ( "abc"
        , "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        , 32
        )
    , ("abc", "5881092dd818bf5cf8a3ddb793fbcba7", 16)
    ]
xofTestVectors "SHAKE256" =
    [
        ( ""
        , "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        , 32
        )
    ,
        ( "abc"
        , "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        , 32
        )
    , ("abc", "483366601360a8771c6863080cc4114d", 16)
    ]
xofTestVectors _ = []

-- incremental updates should produce the same result as a single update
testIncremental :: forall a. XOF a => Tagged a Test
testIncremental = do
    name <- xofName
    let msg = BC.pack "abcdefghijklmnopqrstuvwxyz"
    one <- shake msg 64
    let c1 = xofUpdate (xofInit :: a) (B.take 3 msg)
        c2 = xofUpdate c1 (B.drop 3 (B.take 11 msg))
        c3 = xofUpdate c2 (B.drop 11 msg)
        multi = xofFinalize c3 64
    return $
        testCase ("incremental update " ++ name) $
            assertEqual "incremental SHAKE output equals one-shot" one multi

main =
    defaultMain
        [ testShake `witness` (undefined :: SHAKE128)
        , testShake `witness` (undefined :: SHAKE256)
        , testIncremental `witness` (undefined :: SHAKE128)
        , testIncremental `witness` (undefined :: SHAKE256)
        ]
