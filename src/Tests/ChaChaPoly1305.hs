{-# LANGUAGE OverloadedStrings #-}

import Data.Bits (xor)
import qualified Data.ByteString as B

import Crypto.Nettle.ChaChaPoly1305
import TestUtils

assertChaChaPoly1305
    :: ( B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       )
    -> Assertion
assertChaChaPoly1305 (key, nonce, aad, plain, cipher, tag) = do
    let (cipher', tag') = chaChaPoly1305Encrypt key nonce aad plain
    assertEqualHex "cipher" cipher cipher'
    assertEqualHex "tag" tag tag'
    assertEqual
        "decrypt"
        (Just plain)
        (chaChaPoly1305Decrypt key nonce aad cipher tag)
    assertEqual
        "decrypt wrong tag"
        Nothing
        ( chaChaPoly1305Decrypt
            key
            nonce
            aad
            cipher
            (B.cons (B.head tag `xor` 1) (B.tail tag))
        )

testChaChaPoly1305 :: Test
testChaChaPoly1305 =
    testCases
        "testing ChaChaPoly1305"
        -- source: RFC 8439 section 2.8.2 (A.5)
        [ assertChaChaPoly1305
            ( hs
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            , hs "070000004041424344454647"
            , hs "50515253c0c1c2c3c4c5c6c7"
            , B.pack
                ( map
                    (fromIntegral . fromEnum)
                    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                )
            , hs
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
            , hs "1ae10b594f09e26a7e902ecbd0600691"
            )
        ]

main =
    defaultMain
        [ testChaChaPoly1305
        ]
