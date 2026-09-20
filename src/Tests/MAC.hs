{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString as B

import Crypto.Nettle.CMAC
import Crypto.Nettle.KeyedHash
import Crypto.Nettle.Poly1305
import TestUtils

assertKeyedHash
    :: KeyedHashAlgorithm k
    => (B.ByteString, B.ByteString, String) -> Tagged k Assertion
assertKeyedHash (key, msg, tag) = do
    t' <- keyedHash key msg
    return $ assertEqualHex "" (hs tag) t'

testCMAC :: KeyedHashAlgorithm k => Tagged k Test
testCMAC = do
    name <- implKeyedHashName
    results <- mapM assertKeyedHash (cmacTestVectors name)
    return $ testCases ("testing CMAC " ++ name) results

cmacTestVectors
    :: String -> [(B.ByteString, B.ByteString, String)]
cmacTestVectors "CMAC-AES128" =
    -- source: NIST SP 800-38B test vectors
    [
        ( hs "2b7e151628aed2a6abf7158809cf4f3c"
        , ""
        , "bb1d6929e95937287fa37d129b756746"
        )
    ,
        ( hs "2b7e151628aed2a6abf7158809cf4f3c"
        , hs "6bc1bee22e409f96e93d7e117393172a"
        , "070a16b46b4d4144f79bdd9dd04a287c"
        )
    ,
        ( hs "2b7e151628aed2a6abf7158809cf4f3c"
        , hs
            "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 30c81c46a35ce411"
        , "dfa66747de9ae63030ca32611497c827"
        )
    ]
cmacTestVectors "CMAC-AES256" =
    -- source: NIST SP 800-38B test vectors
    [
        ( hs
            "603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4"
        , ""
        , "028962f61b7bf89efc6b551f4667d983"
        )
    ,
        ( hs
            "603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4"
        , hs "6bc1bee22e409f96e93d7e117393172a"
        , "28a7023f452e8f82bd4bf28d8c37c35c"
        )
    ]
cmacTestVectors "CMAC-DES3" =
    -- source: nettle tests
    [
        ( hs "0123456789abcdeffedcba9876543210 0123456789abcdef"
        , hs "6bc1bee22e409f96e93d7e117393172a"
        , "b45081a29a5df4d0"
        )
    ]
cmacTestVectors _ = []

assertPoly1305
    :: (B.ByteString, B.ByteString, B.ByteString, String) -> Assertion
assertPoly1305 (key, nonce, msg, tag) =
    assertEqualHex "" (hs tag) (poly1305AES key nonce msg)

testPoly1305 :: Test
testPoly1305 =
    testCases
        "testing Poly1305-AES"
        -- source: D. J. Bernstein "The Poly1305-AES message-authentication code",
        -- as used in the nettle test suite
        [ assertPoly1305
            ( hs
                "75deaa25c09f208e1dc4ce6b5cad3fbfa0f3080000f46400d0c7e9076c834403"
            , hs "61ee09218d29b0aaed7e154a2c5509cc"
            , hs ""
            , "dd3fab2251f11ac759f0887129cc2ee7"
            )
        , assertPoly1305
            ( hs
                "ec074c835580741701425b623235add6851fc40c3467ac0be05cc20404f3f700"
            , hs "fb447350c4e868c52ac3275cf9d4327e"
            , hs "f3f6"
            , "f4c633c3044fc145f84f335cb81953de"
            )
        , assertPoly1305
            ( hs
                "6acb5f61a7176dd320c5c1eb2edcdc74 48443d0bb0d21109c89a100b5ce2c208"
            , hs "ae212a55399729595dea458bc621ff0e"
            , hs
                "663cea190ffb83d89593f3f476b6bc24 d7e679107ea26adb8caf6652d0656136"
            , "0ee1c16bb73f0f4fd19881753c01cdbe"
            )
        , assertPoly1305
            ( hs
                "e1a5668a4d5b66a5f68cc5424ed5982d 12976a08c4426d0ce8a82407c4f48207"
            , hs "9ae831e743978d3a23527c7128149e3a"
            , hs
                "ab0812724a7f1e342742cbed374d94d1 36c6b8795d45b3819830f2c04491 faf0990c62e48b8018b2c3e4a0fa3134 cb67fa83e158c994d961c4cb21095c1bf9"
            , "5154ad0d2cb26e01274fc51148491f1b"
            )
        ]

main =
    defaultMain
        [ testCMAC `witness` (undefined :: CMAC_AES128)
        , testCMAC `witness` (undefined :: CMAC_AES256)
        , testCMAC `witness` (undefined :: CMAC_DES3)
        , testPoly1305
        ]
