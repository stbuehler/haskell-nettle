module Ciphers.PropertyTests
	( testBlockCipher
	, testStreamCipher
	) where

-- source: crypto-cipher-tests

import Test.Framework (Test, testGroup)

import Crypto.Cipher.Types

import Ciphers.KAT
import Ciphers.TestModes
import KAT.Utils

-- | Return tests for a specific blockcipher and a list of KATs
testBlockCipher :: BlockCipher a => KATs -> a -> Test
testBlockCipher kats cipher = testGroup (cipherName cipher)
    (  (if kats == defaultKATs  then [] else [testKATs kats cipher])
    ++ testModes cipher
    )

-- | Return tests for a specific streamcipher and a list of KATs
testStreamCipher :: StreamCipher a => [KAT_Stream] -> a -> Test
testStreamCipher kats cipher = testGroup (cipherName cipher)
    (  (if kats == defaultStreamKATs then [] else [testStreamKATs kats cipher])
    ++ testStream cipher
    )
