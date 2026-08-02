
module Ciphers.TestModes
	( testModes
	, testStream
	) where

-- source: crypto-cipher-tests

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck

import Control.Monad (liftM)
import Crypto.Cipher.Types as CCT
import Crypto.Error
import qualified Data.ByteString as B

import Ciphers.Utils
import KAT.Utils

-- | a ECB unit test
data ECBUnit a = ECBUnit B.ByteString a B.ByteString
    deriving (Eq)

instance Show (ECBUnit a) where
    show (ECBUnit k _ b) = "ECB(key=" ++ show k ++ ",input=" ++ show b ++ ")"

-- | a CBC unit test
data CBCUnit a = CBCUnit B.ByteString a (IV a) B.ByteString
    deriving (Eq)

instance (CCT.BlockCipher a) => Show (CBCUnit a) where
    show (CBCUnit k _ iv b) = "CBC(key=" ++ show k ++ ",iv=" ++ show (convertToShowable iv) ++ ",input=" ++ show b ++ ")"

-- | a CFB unit test
data CFBUnit a = CFBUnit B.ByteString a (IV a) B.ByteString
    deriving (Eq)

instance (CCT.BlockCipher a) => Show (CFBUnit a) where
    show (CFBUnit k _ iv b) = "CFB(key=" ++ show k ++ ",iv=" ++ show (convertToShowable iv) ++ ",input=" ++ show b ++ ")"

-- | a CTR unit test
data CTRUnit a = CTRUnit B.ByteString a (IV a) B.ByteString
    deriving (Eq)

instance (CCT.BlockCipher a) => Show (CTRUnit a) where
    show (CTRUnit k _ iv b) = "CTR(key=" ++ show k ++ ",iv=" ++ show (convertToShowable iv) ++ ",input=" ++ show b ++ ")"

-- | a AEAD unit test
data AEADUnit a = AEADUnit B.ByteString a (IV a) B.ByteString B.ByteString
    deriving (Eq)

instance (CCT.BlockCipher a) => Show (AEADUnit a) where
    show (AEADUnit k _ iv aad b) = "AEAD(key=" ++ show k ++ ",iv=" ++ show (convertToShowable iv) ++ ",aad=" ++ show aad ++ ",input=" ++ show b ++ ")"

-- | a Stream unit test
data StreamUnit a = StreamUnit B.ByteString a B.ByteString
    deriving (Eq)

instance Show (StreamUnit a) where
    show (StreamUnit k _ b) = "Stream(key=" ++ show k ++ ",input=" ++ show b ++ ")"

getKey :: Key a b -> b
getKey (Key _ b) = b

genPlaintextBlocks :: CCT.BlockCipher cipher => Gen cipher -> Gen B.ByteString
genPlaintextBlocks c = do
            c' <- c
            blocks <- choose (1,128)
            genBlockCipherInput c' blocks

genPlaintext :: CCT.Cipher cipher => Gen cipher -> Gen B.ByteString
genPlaintext c = do
            c' <- c
            blocks <- choose (1,324)
            genUnalignedBlockCipherInput c' blocks

instance CCT.BlockCipher a => Arbitrary (ECBUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        p = genPlaintextBlocks c
        in ECBUnit <$> (liftM getKey k) <*> c <*> p

instance CCT.BlockCipher a => Arbitrary (CBCUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        iv = c >>= genIV
        p = genPlaintextBlocks c
        in CBCUnit <$> (liftM getKey k) <*> c <*> iv <*> p

instance CCT.BlockCipher a => Arbitrary (CFBUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        iv = c >>= genIV
        p = genPlaintextBlocks c
        in CFBUnit <$> (liftM getKey k) <*> c <*> iv <*> p

instance CCT.BlockCipher a => Arbitrary (CTRUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        iv = c >>= genIV
        p = genPlaintext c
        in CTRUnit <$> (liftM getKey k) <*> c <*> iv <*> p

instance CCT.BlockCipher a => Arbitrary (AEADUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        iv = c >>= genIV
        aad = genPlaintext c
        p = genPlaintext c
        in AEADUnit <$> (liftM getKey k) <*> c <*> iv <*> aad <*> p

instance CCT.StreamCipher a => Arbitrary (StreamUnit a) where
    arbitrary = let
        k = genTypedKey undefined
        c = liftM initCipher k
        p = genPlaintext c
        in StreamUnit <$> (liftM getKey k) <*> c <*> p

-- | Test a generic block cipher for properties
-- related to block cipher modes.
testModes :: CCT.BlockCipher a => a -> [Test]
testModes cipher =
    [ testGroup "decrypt.encrypt==id"
        (testBlockCipherBasic cipher ++ testBlockCipherModes cipher ++ testBlockCipherAEAD cipher)
    ]

testBlockCipherBasic :: CCT.BlockCipher a => a -> [Test]
testBlockCipherBasic cipher = [ testProperty "ECB" ecbProp ]
  where ecbProp = toTests cipher
        toTests :: CCT.BlockCipher a => a -> ECBUnit a -> Bool
        toTests _ = testProperty_ECB
        testProperty_ECB (ECBUnit _ ctx plaintext) =
            plaintext `assertEq` CCT.ecbDecrypt ctx (CCT.ecbEncrypt ctx plaintext)

testBlockCipherModes :: CCT.BlockCipher a => a -> [Test]
testBlockCipherModes cipher =
    [ testProperty "CBC" cbcProp
    , testProperty "CFB" cfbProp
    , testProperty "CTR" ctrProp
    ]
  where (cbcProp,cfbProp,ctrProp) = toTests cipher
        toTests :: CCT.BlockCipher a
                => a
                -> ((CBCUnit a -> Bool), (CFBUnit a -> Bool), (CTRUnit a -> Bool))
        toTests _ = (testProperty_CBC
                    ,testProperty_CFB
                    ,testProperty_CTR
                    )
        testProperty_CBC (CBCUnit _ ctx testIV plaintext) =
            plaintext `assertEq` CCT.cbcDecrypt ctx testIV (CCT.cbcEncrypt ctx testIV plaintext)

        testProperty_CFB (CFBUnit _ ctx testIV plaintext) =
            plaintext `assertEq` CCT.cfbDecrypt ctx testIV (CCT.cfbEncrypt ctx testIV plaintext)

        testProperty_CTR (CTRUnit _ ctx testIV plaintext) =
            plaintext `assertEq` CCT.ctrCombine ctx testIV (CCT.ctrCombine ctx testIV plaintext)

testBlockCipherAEAD :: CCT.BlockCipher a => a -> [Test]
testBlockCipherAEAD cipher =
    [ testProperty "OCB" (aeadProp CCT.AEAD_OCB)
    , testProperty "CCM" (aeadProp (CCT.AEAD_CCM 0 CCM_M16 CCM_L2))
    , testProperty "EAX" (aeadProp CCT.AEAD_EAX)
    , testProperty "CWC" (aeadProp CCT.AEAD_CWC)
    , testProperty "GCM" (aeadProp CCT.AEAD_GCM)
    ]
  where aeadProp = toTests cipher
        toTests :: CCT.BlockCipher a => a -> (CCT.AEADMode -> AEADUnit a -> Bool)
        toTests _ = testProperty_AEAD
        testProperty_AEAD mode (AEADUnit _ ctx testIV aad plaintext) =
            case aeadInit mode ctx testIV of
                CryptoPassed iniAead ->
                    let aead           = CCT.aeadAppendHeader iniAead aad
                        (eText, aeadE) = CCT.aeadEncrypt aead plaintext
                        (dText, aeadD) = CCT.aeadDecrypt aead eText
                        eTag           = CCT.aeadFinalize aeadE (blockSize ctx)
                        dTag           = CCT.aeadFinalize aeadD (blockSize ctx)
                     in (plaintext `assertEq` dText) && (eTag `assertEq` dTag)
                CryptoFailed _ -> True

-- | Test stream mode
testStream :: CCT.StreamCipher a => a -> [Test]
testStream cipher = [testProperty "combine.combine==id" (testStreamUnit cipher)]
  where testStreamUnit :: CCT.StreamCipher a => a -> (StreamUnit a -> Bool)
        testStreamUnit _ (StreamUnit _ ctx plaintext) =
            let cipherText = fst $ CCT.streamCombine ctx plaintext
             in fst (CCT.streamCombine ctx cipherText) `assertEq` plaintext
