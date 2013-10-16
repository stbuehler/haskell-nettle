{-# LANGUAGE CPP #-}

module Nettle.Utils
	( Ptr
	, plusPtr
	, FunPtr
	, Word8
	, Word
	, unsafeDupablePerformIO
	, withByteStringPtr
	, netEncode
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Foreign.Ptr (Ptr, plusPtr, FunPtr)
import Foreign.ForeignPtr (withForeignPtr)
import Data.Word (Word8, Word)

import System.IO.Unsafe (unsafeDupablePerformIO)

-- from hs-cipher-rc4

withByteStringPtr :: B.ByteString -> (Word -> Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f = withForeignPtr fptr $ \ptr -> f (fromIntegral len) (ptr `plusPtr` off)
	where (fptr, off, len) = B.toForeignPtr b

netEncode :: (Integral n) => Int -> n -> [Word8]
netEncode bytes value = _work bytes [] value where
	_work 0 r _ = r
	_work n r v = let (d, m) = divMod v 256 in _work (n-1) (fromIntegral m:r) d
