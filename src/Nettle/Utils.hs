{-# LANGUAGE CPP #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Crypto.Nettle.Hash.Types
-- Copyright   :  (c) 2013 Stefan Bühler
-- License     :  MIT-style (see the file COPYING)
-- 
-- Maintainer  :  stbuehler@web.de
-- Stability   :  experimental
-- Portability :  portable
--
-- Collection of internal utility functions and exports of common imports
--
-----------------------------------------------------------------------------

module Nettle.Utils
	( Ptr
	, plusPtr
	, FunPtr
	, Word8
	, Word
	, forM_
	, unsafeDupablePerformIO
	, withByteStringPtr
	, copyScrubbedBytes
	, copyAndConvertToScrubbedBytes
	, createScrubbedBytes
	, concatToScrubbedBytes
	, netEncode
	) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Foreign.Ptr (Ptr, plusPtr, FunPtr)
import Foreign.ForeignPtr (withForeignPtr)
import Data.Word (Word8, Word)
import Control.Monad (forM_)

import System.IO.Unsafe (unsafeDupablePerformIO)

{-|
Run action in IO monad with length and pointer to first byte of a 'B.ByteString'
-}
withByteStringPtr :: B.ByteString -> (Word -> Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f = withForeignPtr fptr $ \ptr -> f (fromIntegral len) (ptr `plusPtr` off)
	where (fptr, off, len) = B.toForeignPtr b

{-|
Copy a 'BA.ScrubbedBytes'.
-}
copyScrubbedBytes :: BA.ScrubbedBytes -> BA.ScrubbedBytes
copyScrubbedBytes ba = BA.copyAndFreeze ba (\_ -> return ())

{-|
Make a copy of a 'BA.ByteArrayAccess' that gets scrubbed.
-}
copyAndConvertToScrubbedBytes :: BA.ByteArrayAccess a => a -> BA.ScrubbedBytes
copyAndConvertToScrubbedBytes = BA.convert

{-|
Create a 'BA.ScrubbedBytes'. Used for type hinting.
-}
createScrubbedBytes :: Int -> (Ptr p -> IO ()) -> IO BA.ScrubbedBytes
createScrubbedBytes = BA.create

{-|
Concatenate a 'BA.ByteArrayAccess' to a 'BA.ScrubbedBytes'. Used for type hinting.
-}
concatToScrubbedBytes :: BA.ByteArrayAccess a => [a] -> BA.ScrubbedBytes
concatToScrubbedBytes = BA.concat

{-|
Encode any 'Integral' @value@ in @bytes@ 'Word8' as big endian value.
-}
netEncode :: (Integral n) => Int {- ^ @bytes@ argument -} -> n {- ^ @value@ argument -} -> [Word8]
netEncode bytes = _work bytes [] where
	_work 0 r _ = r
	_work n r v = let (d, m) = divMod v 256 in _work (n-1) (fromIntegral m:r) d
