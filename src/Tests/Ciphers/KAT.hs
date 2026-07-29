
module Ciphers.KAT
	( testKATs
	, testStreamKATs
	) where

import Test.Framework (Test, TestName, testGroup)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit ((@?=))
import Crypto.Cipher.Types as CCT
import qualified Data.ByteArray as BA

import Ciphers.Utils
import KAT.Utils

-- | tests related to KATs
testKATs :: CCT.BlockCipher cipher
         => KATs
         -> cipher
         -> Test
testKATs kats cipher = testGroup "KAT"
    (   maybeGroup makeECBTest "ECB" (kat_ECB kats)
    )
  where makeECBTest i d =
            [ testCase ("E" ++ i) (CCT.ecbEncrypt ctx (ecbPlaintext d) @?= ecbCiphertext d)
            , testCase ("D" ++ i) (CCT.ecbDecrypt ctx (ecbCiphertext d) @?= ecbPlaintext d)
            ]
          where ctx = initCipher (Key cipher (ecbKey d))
               
testStreamKATs :: CCT.StreamCipher cipher => [KAT_Stream] -> cipher -> Test
testStreamKATs kats cipher = testGroup "KAT" $ maybeGroup makeStreamTest "Stream" kats
  where makeStreamTest i d =
            [ testCase ("E" ++ i) (fst (CCT.streamCombine ctx (streamPlaintext d)) @?= streamCiphertext d)
            , testCase ("D" ++ i) (fst (CCT.streamCombine ctx (streamCiphertext d)) @?= streamPlaintext d)
            ]
          where ctx = initCipher (Key cipher (streamKey d))

maybeGroup :: (String -> t -> [Test]) -> TestName -> [t] -> [Test]
maybeGroup mkTest groupName l
    | null l    = []
    | otherwise = [testGroup groupName (concatMap (\(i, d) -> mkTest (show i) d) $ zip [0..] l)]
