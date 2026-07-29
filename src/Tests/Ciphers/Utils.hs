
module Ciphers.Utils
	( Key(..)
	, genByteString
	, genKey'
	, genKey
	, genTypedKey
	, runCryptoFailable
	, genCipher
	, genIV
	, genUnalignedBlockCipherInput
	, genBlockCipherInput
	, initCipher
	, convertToShowable
	, assertEq
	) where

import Test.QuickCheck (Gen(..), elements, choose, vectorOf)

import Control.Monad (liftM)
import Crypto.Cipher.Types as CCT
import Crypto.Error
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

data Key c a = Key c a

genByteString :: Int -> Gen B.ByteString
genByteString len = liftM B.pack $ vectorOf len (choose (0,255))

runMaybe :: (Monad m) => Maybe x -> m x
runMaybe Nothing = error "got nothing"
runMaybe (Just x) = return x

genKey' :: CCT.KeySizeSpecifier -> Gen B.ByteString
genKey' spec = case spec of
	CCT.KeySizeRange bot top -> choose (bot, top) >>= genByteString
	CCT.KeySizeEnum list     -> elements list >>= genByteString
	CCT.KeySizeFixed f       -> genByteString f

genKey :: CCT.Cipher c => c -> Gen (B.ByteString)
genKey c = genKey' (CCT.cipherKeySize c)

genTypedKey :: CCT.Cipher c => c -> Gen (Key c B.ByteString)
genTypedKey c = liftM (Key c) $ genKey' (CCT.cipherKeySize c)

runCryptoFailable :: CCT.Cipher c => CryptoFailable c -> c
runCryptoFailable (CryptoFailed e) = error $ show e
runCryptoFailable (CryptoPassed x) = x

genCipher :: CCT.Cipher c => c -> Gen c
genCipher c = liftM (runCryptoFailable . CCT.cipherInit) $ (genKey c)

genIV :: CCT.BlockCipher c => c -> Gen (IV c)
genIV c = genByteString (CCT.blockSize c) >>= runMaybe . CCT.makeIV

genBlockCipherInput :: CCT.BlockCipher c => c -> Int -> Gen B.ByteString
genBlockCipherInput c blocks = genByteString (CCT.blockSize c * blocks)

genUnalignedBlockCipherInput :: CCT.Cipher c => c -> Int -> Gen B.ByteString
genUnalignedBlockCipherInput c bytes = genByteString bytes

initCipher :: (CCT.Cipher c, BA.ByteArray ba) => Key c ba -> c
initCipher (Key _ k) = runCryptoFailable $ CCT.cipherInit k

convertToShowable :: BA.ByteArrayAccess a => a -> BA.Bytes
convertToShowable = BA.convert

assertEq :: (BA.ByteArrayAccess a, BA.ByteArrayAccess b) => a -> b -> Bool
assertEq b1 b2 | BA.eq b1 b2 = True
               | otherwise = error ("b1: " ++ show (convertToShowable b1) ++ " b2: " ++ show (convertToShowable b2))
