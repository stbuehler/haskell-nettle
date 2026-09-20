{-# LANGUAGE OverloadedStrings #-}

import Data.Bits (xor)
import qualified Data.ByteString as B

import Crypto.Nettle.EAX
import Crypto.Nettle.OCB
import Crypto.Nettle.SIV
import TestUtils

assertEncryptDecrypt
    :: ( B.ByteString
         -> B.ByteString
         -> B.ByteString
         -> B.ByteString
         -> (B.ByteString, B.ByteString)
       )
    -> ( B.ByteString
         -> B.ByteString
         -> B.ByteString
         -> B.ByteString
         -> B.ByteString
         -> Maybe B.ByteString
       )
    -> ( B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       , B.ByteString
       )
    -> Assertion
assertEncryptDecrypt encrypt decrypt (key, nonce, aad, plain, cipher, tag) = do
    let badtag = B.cons (B.head tag `xor` 0x01) (B.tail tag)
    assertEqualHex
        "cipher"
        cipher
        (fst (encrypt key nonce aad plain))
    assertEqualHex "tag" tag (snd (encrypt key nonce aad plain))
    assertEqual
        "decrypt"
        (Just plain)
        (decrypt key nonce aad cipher tag)
    assertEqual
        "decrypt wrong tag"
        Nothing
        (decrypt key nonce aad cipher badtag)
    assertEqual
        "decrypt corrupt cipher"
        Nothing
        ( decrypt
            key
            nonce
            aad
            (B.take (B.length cipher - 1) cipher `B.append` B.singleton 0x00)
            tag
        )

testEAX :: Test
testEAX =
    testCases
        "testing EAX"
        -- source: the EAX specification (Bellare, Rogaway, Wagner),
        -- http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
        -- output layout: ciphertext || tag
        [ assertEncryptDecrypt
            eaxAES128Encrypt
            eaxAES128Decrypt
            ( hs "233952DEE4D5ED5F9B9C6D6FF80FF478"
            , hs "62EC67F9C3A4A407FCB2A8C49031A8B3"
            , hs "6BFB914FD07EAE6B"
            , hs ""
            , hs ""
            , hs "E037830E8389F27B025A2D6527E79D01"
            )
        , assertEncryptDecrypt
            eaxAES128Encrypt
            eaxAES128Decrypt
            ( hs "91945D3F4DCBEE0BF45EF52255F095A4"
            , hs "BECAF043B0A23D843194BA972C66DEBD"
            , hs "FA3BFD4806EB53FA"
            , hs "F7FB"
            , hs "19DD"
            , hs "5C4C9331049D0BDAB0277408F67967E5"
            )
        , assertEncryptDecrypt
            eaxAES128Encrypt
            eaxAES128Decrypt
            ( hs "01F74AD64077F2E704C0F60ADA3DD523"
            , hs "70C3DB4F0D26368400A10ED05D2BFF5E"
            , hs "234A3463C1264AC6"
            , hs "1A47CB4933"
            , hs "D851D5BAE0"
            , hs "3A59F238A23E39199DC9266626C40F80"
            )
        , assertEncryptDecrypt
            eaxAES128Encrypt
            eaxAES128Decrypt
            ( hs "D07CF6CBB7F313BDDE66B727AFD3C5E8"
            , hs "8408DFFF3C1A2B1292DC199E46B7D617"
            , hs "33CCE2EABFF5A79D"
            , hs "481C9E39B1"
            , hs "632A9D131A"
            , hs "D4C168A4225D8E1FF755939974A7BEDE"
            )
        ]

testOCB :: Test
testOCB =
    testCases
        "testing OCB"
        -- source: RFC 7253 test vectors
        -- output layout: ciphertext || tag
        [ assertEncryptDecrypt
            ocbAES128Encrypt
            ocbAES128Decrypt
            ( hs "000102030405060708090A0B0C0D0E0F"
            , hs "BBAA99887766554433221100"
            , hs ""
            , hs ""
            , hs ""
            , hs "785407BFFFC8AD9EDCC5520AC9111EE6"
            )
        , assertEncryptDecrypt
            ocbAES128Encrypt
            ocbAES128Decrypt
            ( hs "000102030405060708090A0B0C0D0E0F"
            , hs "BBAA99887766554433221101"
            , hs "0001020304050607"
            , hs "0001020304050607"
            , hs "6820B3657B6F615A"
            , hs "5725BDA0D3B4EB3A257C9AF1F8F03009"
            )
        , assertEncryptDecrypt
            ocbAES128Encrypt
            ocbAES128Decrypt
            ( hs "000102030405060708090A0B0C0D0E0F"
            , hs "BBAA99887766554433221103"
            , hs ""
            , hs "0001020304050607"
            , hs "45DD69F8F5AAE724"
            , hs "14054CD1F35D82760B2CD00D2F99BFA9"
            )
        , assertEncryptDecrypt
            ocbAES128Encrypt
            ocbAES128Decrypt
            ( hs "000102030405060708090A0B0C0D0E0F"
            , hs "BBAA9988776655443322110A"
            , hs
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            , hs
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            , hs
                "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A485"
            , hs "40FBBA186C5553C68AD9F592A79A4240"
            )
        ]

testSIV128 :: Test
testSIV128 =
    testCases
        "testing SIV (AES-128)"
        -- source: RFC 5297 test vectors
        -- output layout: tag || ciphertext
        [ assertEncryptDecrypt
            sivAES128Encrypt
            sivAES128Decrypt
            ( hs
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            , hs "01"
            , hs ""
            , hs ""
            , hs ""
            , hs "c696f84fdf92aba3c31c23d5f2087513"
            )
        , assertEncryptDecrypt
            sivAES128Encrypt
            sivAES128Decrypt
            ( hs
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            , hs "02"
            , hs ""
            , hs "00112233445566778899aabbccddeeff"
            , hs "1f259d405bfa260b9ba1d60aa287fd0b"
            , hs "5027b101589747b8865a9790d3fd51d7"
            )
        , assertEncryptDecrypt
            sivAES128Encrypt
            sivAES128Decrypt
            ( hs
                "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"
            , hs "020304"
            , hs
                "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
            , hs
                "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"
            , hs
                "a4ffb87fdba97c8944a62325f133b4e01ca55276e2261c1a1d1d4248d1da30ba52b9c8d7955d65c8d2ce6eb7e367d0"
            , hs "f1dba33de5b3369e883f67b6fc823cee"
            )
        ]

testSIV256 :: Test
testSIV256 =
    testCases
        "testing SIV (AES-256)"
        -- source: RFC 5297 test vectors
        -- output layout: tag || ciphertext
        [ assertEncryptDecrypt
            sivAES256Encrypt
            sivAES256Decrypt
            ( hs
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f"
            , hs "02"
            , hs "101112131415161718191a1b1c1d1e1f2021222324252627"
            , hs "112233445566778899aabbccddee"
            , hs "ad9e6ff14ea97c32ab315e67464c"
            , hs "6f740b421e2972d85e76189e99842843"
            )
        ]

main =
    defaultMain
        [ testEAX
        , testOCB
        , testSIV128
        , testSIV256
        ]
