{-# LANGUAGE CPP #-}

module Nettle.Utils
	( Ptr
	, plusPtr
	, FunPtr
	, Word8
	, Word
	, unsafeDupablePerformIO
	, withByteStringPtr
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
