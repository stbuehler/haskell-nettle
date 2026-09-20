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

	, AlignedContext
	, alignedCtxCreate
	, alignedCtxCopy
	, alignedCtxBuffer
	, alignedCtxOffset
	, withAlignedContext
	) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Foreign.Ptr (Ptr, plusPtr, FunPtr, ptrToWordPtr)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Utils (copyBytes)
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

-- Nettle 4 implementations (GCM, CMAC, EAX, OCB, SIV, ...) use 16-byte
-- aligned accesses on parts of their contexts, while @ram@'s 'ScrubbedBytes'
-- only guarantees 8-byte alignment.  Contexts are therefore over-allocated
-- with padding, and the pointer handed to C is aligned to a 16-byte boundary.
-- The byte offset to the aligned start of a buffer is stored alongside it;
-- because 'copyScrubbedBytes' would not preserve the alignment of the copied
-- data, copies re-place the context struct into the aligned region of a
-- freshly allocated buffer.

-- | The alignment required by Nettle contexts that contain 16-byte aligned members.
alignedCtxAlignment :: Int
alignedCtxAlignment = 16

-- | An over-allocated 'BA.ScrubbedBytes' buffer together with the offset of the
--   aligned start of the context struct within it.
data AlignedContext = AlignedContext !Int !BA.ScrubbedBytes

alignedCtxSize :: Int -> Int
alignedCtxSize n = n + alignedCtxAlignment - 1

alignedCtxOffset :: AlignedContext -> Int
alignedCtxOffset (AlignedContext off _) = off

alignedCtxBuffer :: AlignedContext -> BA.ScrubbedBytes
alignedCtxBuffer (AlignedContext _ buf) = buf

-- | The offset (relative to the buffer start) of the 16-byte aligned region.
alignedCtxOffsetFromBase :: BA.ScrubbedBytes -> Int
alignedCtxOffsetFromBase ba = unsafeDupablePerformIO $
	BA.withByteArray ba $ \p ->
		return (fromIntegral ((fromIntegral alignedCtxAlignment - ptrToWordPtr p `mod` fromIntegral alignedCtxAlignment) `mod` fromIntegral alignedCtxAlignment))

-- | Run an IO action with a pointer to the aligned start of a freshly allocated,
--   zeroed, over-allocated buffer; returns the resulting context with offset.
alignedCtxCreate :: Int -> (Ptr Word8 -> IO ()) -> IO AlignedContext
alignedCtxCreate size act = do
	buf <- BA.create (alignedCtxSize size) (return . const ())
	let off = alignedCtxOffsetFromBase buf
	BA.withByteArray buf $ \p -> act (p `plusPtr` off)
	return $ AlignedContext off buf

-- | Run an IO action with a pointer to the aligned start of a freshly allocated,
--   zeroed, over-allocated buffer; returns the result of the action.
withAlignedContext :: Int -> (Ptr Word8 -> IO a) -> IO a
withAlignedContext size act = do
	buf <- BA.create (alignedCtxSize size) (return . const ())
	let off = alignedCtxOffsetFromBase buf
	BA.withByteArray buf $ \p -> act (p `plusPtr` off)

-- | Copy the @size@-byte context struct from @src@ into the aligned region of a
--   fresh zeroed buffer, then run an IO action with a pointer to it; returns the
--   resulting context with offset.
alignedCtxCopy :: AlignedContext -> Int -> (Ptr Word8 -> IO ()) -> IO AlignedContext
alignedCtxCopy (AlignedContext srcOff src) size act = do
	dst <- BA.create (alignedCtxSize size) (return . const ())
	let dstOff = alignedCtxOffsetFromBase dst
	BA.withByteArray dst $ \dptr ->
		BA.withByteArray src $ \sptr ->
			copyBytes (dptr `plusPtr` dstOff) (sptr `plusPtr` srcOff) size
	BA.withByteArray dst $ \p -> act (p `plusPtr` dstOff)
	return $ AlignedContext dstOff dst
