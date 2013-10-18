
module TestUtils
	( defaultMain
	, testGroup
	, Test(..)

	, assertEqual
	, Assertion
	, testCase

	, testCases
	, debugTestCases

	, readHex'
	, readHex
	, toString
	, hs

	, assertEqualHex

	, module Data.Tagged
	, Word8
	) where

import qualified Numeric as N

import Test.Framework (defaultMain, testGroup, Test(..))
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit (assertEqual, assertBool, Assertion)

import Data.Word (Word8)
import Data.Tagged
import qualified Data.ByteString as B
import qualified Data.Array.IArray as A

readHex' :: Monad m => String -> m [Word8]
readHex' [] = return []
readHex' (' ':xs) = readHex' xs
readHex' (a:' ':xs) = readHex' $ a:xs
readHex' (a:b:xs) = do
	n <- case (N.readHex (a:b:[])) of
		(n, ""):_ -> return n
		_ -> fail "invalid hex encoding"
	xn <- readHex' xs
	return $ n:xn
readHex' _ = fail "invalid hex encoding"

readHex :: String -> [Word8]
readHex s = let Just r = readHex' s in r

toString :: [Word8] -> String
toString = map (toEnum . fromIntegral)

-- read hex string
hs :: String -> B.ByteString
hs = B.pack . readHex

testCases :: String -> [Assertion] -> Test
testCases title = testCase title . mapM_ id

debugTestCases :: String -> [Assertion] -> Test
debugTestCases title = testGroup title . zipWith (\n c -> testCase (show n) c) [1..]

hexchars :: A.Array Word8 Char
hexchars = A.listArray (0,15) (['0'..'9'] ++ ['a'..'f'])

hexa :: [Word8] -> String
hexa [] = []
hexa (x:xs) = let (high,low) = divMod x 16 in hexchars A.! high:hexchars A.! low:hexa xs

hexs :: B.ByteString -> String
hexs = hexa . B.unpack

assertEqualHex :: String -> B.ByteString -> B.ByteString -> Assertion
assertEqualHex preface expected actual = assertBool msg (actual == expected) where
	msg = (if null preface then "" else preface ++ "\n") ++ "\texpected: " ++ hexs expected ++ "\n\t but got: " ++ hexs actual
