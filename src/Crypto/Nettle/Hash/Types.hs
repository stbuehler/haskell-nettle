{-# LANGUAGE ExistentialQuantification, MultiParamTypeClasses, FunctionalDependencies #-}

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
-- Collection of internal types due to cyclic dependencies
--
-----------------------------------------------------------------------------

module Crypto.Nettle.Hash.Types
	( HashAlgorithm(..)
	, hash
	, hash'
	, hashLazy
	, hashLazy'

	, KeyedHashAlgorithm(..)
	, KeyedHash

	, keyedHashDigestSize
	, keyedHashDigestSize'
	, keyedHashName
	, keyedHashName'
	, keyedHashInit
	, keyedHashInit'
	, keyedHashInitPrivate
	, keyedHashUpdate
	, keyedHashUpdateLazy
	, keyedHashFinalize
	, keyedHash
	, keyedHash'
	, keyedHashLazy
	, keyedHashLazy'

	, module Data.Tagged

	, HMAC
	, HMACState
	, hmacInit
	, hmacInit'
	, hmac
	, hmac'
	, hmacLazy
	, hmacLazy'
	) where

import Data.Tagged
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Control.Applicative ((<$>))
import Data.Bits (xor)
import Data.List (foldl')


{-|
'HashAlgorithm' is a class that hash algorithms will implement. generating a digest is a 3 step procedure:

  * 'hashInit' to create a new context

  * 'hashUpdate' to hash data

  * 'hashFinalize' to extract the final digest

The final digest has 'hashDigestSize' bytes, and the algorithm uses 'hashBlockSize' as internal block size.
-}
class HashAlgorithm a where
	-- | Block size in bytes the hash algorithm operates on
	hashBlockSize  :: Tagged a Int
	-- | Digest size in bytes the hash algorithm returns
	hashDigestSize :: Tagged a Int
	-- | Name of the hash algorithm
	hashName       :: Tagged a String
	-- | Initialize a new context for this hash algorithm
	hashInit       :: a
	-- | Update the context with bytestring, and return a new context with the updates.
	hashUpdate     :: a -> B.ByteString -> a
	-- | Update the context with a lazy bytestring, and return a new context with the updates.
	hashUpdateLazy :: a -> L.ByteString -> a
	hashUpdateLazy a = foldl' hashUpdate a . L.toChunks
	-- | Finalize a context and return a digest.
	hashFinalize   :: a -> B.ByteString
	-- | Use 'HashAlgorithm' for HMAC; can use a optimized variant or the default 'hmacInit' one
	hashHMAC       :: B.ByteString -> Tagged a KeyedHash
	hashHMAC = hmacInit

{-|
Helper to hash a single (strict) 'B.ByteString' in one step.

Example:

> untag (hash (fromString "abc") :: Tagged SHA256 B.ByteString)
-}
hash :: HashAlgorithm a => B.ByteString -> Tagged a B.ByteString
hash msg = hashFinalize <$> flip hashUpdate msg <$> tagSelf hashInit
{-|
Untagged variant of 'hash'; takes a (possible 'undefined') typed 'HashAlgorithm' context as parameter.

Example:

> hash' (undefined :: SHA256) $ fromString "abc"
-}
hash' :: HashAlgorithm a => a -> B.ByteString -> B.ByteString
hash' a = flip witness a . hash

{-|
Helper to hash a single (lazy) 'L.ByteString' in one step.

Example:

> untag (hashLazy (fromString "abc") :: Tagged SHA256 L.ByteString)
-}
hashLazy :: HashAlgorithm a => L.ByteString -> Tagged a L.ByteString
hashLazy msg = L.fromStrict <$> hashFinalize <$> flip hashUpdateLazy msg <$> tagSelf hashInit
{-|
Untagged variant of 'hashLazy'; takes a (possible 'undefined') typed 'HashAlgorithm' context as parameter.

Example:

> hashLazy' (undefined :: SHA256) $ fromString "abc"
-}
hashLazy' :: HashAlgorithm a => a -> L.ByteString -> L.ByteString
hashLazy' a = flip witness a . hashLazy

{-|
'KeyedHashAlgorithm' is a class for keyed hash algorithms that take a key and a message to produce a digest.
The most popular example is 'HMAC'.

A 'KeyedHashAlgorithm' will operate on a fixed key @k@ and a state @s@; @s@ will be updated as messages
are added.

On start an implementation will generate the fixed key @k@ and an initial state @s@ from a 'B.ByteString' key.
-}
class KeyedHashAlgorithm k s | k -> s where
	-- | Digest size in bytes the keyed hash algorithm returns
	implKeyedHashDigestSize :: Tagged k Int
	-- | Name
	implKeyedHashName :: Tagged k String
	-- | Initialize state from a key
	implKeyedHashInit :: B.ByteString -> (k, s)
	-- | Add more message data to the state
	implKeyedHashUpdate :: k -> s -> B.ByteString -> s
	-- | Add more lazy message data to the state
	implKeyedHashUpdateLazy :: k -> s -> L.ByteString -> s
	implKeyedHashUpdateLazy k s = foldl' (implKeyedHashUpdate k) s . L.toChunks
	-- | Produce final digest
	implKeyedHashFinalize :: k -> s -> B.ByteString

{-|
'KeyedHash' hides the 'KeyedHashAlgorithm' implementation; it contains the fixed key and the current state.
-}
data KeyedHash = forall k s. KeyedHashAlgorithm k s => KeyedHash k s

{-|
Untagged variant of 'implKeyedHashDigestSize'; takes a (possible 'undefined') key typed value from a 'KeyedHashAlgorithm' instance as parameter.
-}
keyedHashDigestSize :: KeyedHashAlgorithm k s => k -> Int
keyedHashDigestSize k = implKeyedHashDigestSize `witness` k
{-|
Get 'implKeyedHashDigestSize' from a 'KeyedHash'
-}
keyedHashDigestSize' :: KeyedHash -> Int
keyedHashDigestSize' (KeyedHash k _) = implKeyedHashDigestSize `witness` k
{-|
Untagged variant of 'implKeyedHashName'; takes a (possible 'undefined') key typed value from a 'KeyedHashAlgorithm' instance as parameter.
-}
keyedHashName :: KeyedHashAlgorithm k s => k -> String
keyedHashName k = implKeyedHashName `witness` k
{-|
Get 'implKeyedHashName' from a 'KeyedHash'
-}
keyedHashName' :: KeyedHash -> String
keyedHashName' (KeyedHash k _) = implKeyedHashName `witness` k
{-|
Initialize a 'KeyedHash' context from a @key@
-}
keyedHashInit :: KeyedHashAlgorithm k s => B.ByteString {- ^ @key@ argument -} -> Tagged k KeyedHash
keyedHashInit key = let (k, s) = implKeyedHashInit key in tagSelf k >> return (KeyedHash k s)
{-|
Untagged variant of 'keyedHashInit'; takes a (possible 'undefined') key typed value from a 'KeyedHashAlgorithm' instance as parameter.
-}
keyedHashInit' :: KeyedHashAlgorithm k s => k -> B.ByteString -> KeyedHash
keyedHashInit' k key = keyedHashInit key `witness` k
{-|
Allow custom creation of a 'KeyedHash' context by an implementation that might need more than a @key@.
-}
keyedHashInitPrivate :: KeyedHashAlgorithm k s => k -> s -> KeyedHash
keyedHashInitPrivate = KeyedHash
{-|
Add more message data to the context
-}
keyedHashUpdate :: KeyedHash -> B.ByteString -> KeyedHash
keyedHashUpdate (KeyedHash k s) = KeyedHash k . implKeyedHashUpdate k s
{-|
Add more lazy message data to the context
-}
keyedHashUpdateLazy :: KeyedHash -> L.ByteString -> KeyedHash
keyedHashUpdateLazy (KeyedHash k s) = KeyedHash k . implKeyedHashUpdateLazy k s
{-|
Produce final digest
-}
keyedHashFinalize :: KeyedHash -> B.ByteString
keyedHashFinalize (KeyedHash k s) = implKeyedHashFinalize k s
{-|
Helper to hash @key@ and @message@ in one step

Example:

> untag (keyedHash (fromString "secretkey") (fromString "secret message") :: Tagged (HMAC SHA256) B.ByteString)
-}
keyedHash :: KeyedHashAlgorithm k s => B.ByteString -> B.ByteString -> Tagged k B.ByteString
keyedHash key msg = keyedHashFinalize <$> flip keyedHashUpdate msg <$> keyedHashInit key
{-|
Untagged variant of 'keyedHash'; takes a (possible 'undefined') key typed value from a 'KeyedHashAlgorithm' instance as parameter.

Example:

> keyedHash' (undefined :: HMAC SHA256) (fromString "secretkey") (fromString "secret message")
-}
keyedHash' :: KeyedHashAlgorithm k s => k -> B.ByteString -> B.ByteString -> B.ByteString
keyedHash' k key msg = keyedHash key msg `witness` k
{-|
Helper to hash @key@ and lazy @message@ in one step

Example:

> untag (keyedHashLazy (fromString "secretkey") (fromString "secret message") :: Tagged (HMAC SHA256) B.ByteString)
-}
keyedHashLazy :: KeyedHashAlgorithm k s => B.ByteString -> L.ByteString -> Tagged k B.ByteString
keyedHashLazy key msg = keyedHashFinalize <$> flip keyedHashUpdateLazy msg <$> keyedHashInit key
{-|
Untagged variant of 'keyedHashLazy'; takes a (possible 'undefined') key typed value from a 'KeyedHashAlgorithm' instance as parameter.

Example:

> keyedHashLazy' (undefined :: HMAC SHA256) (fromString "secretkey") (fromString "secret message")
-}
keyedHashLazy' :: KeyedHashAlgorithm k s => k -> B.ByteString -> L.ByteString -> B.ByteString
keyedHashLazy' k key msg = keyedHashLazy key msg `witness` k

{-|
'HMAC' is the key for a 'KeyedHashAlgorithm' instance to calculate the 'HMAC' based
on a 'HashAlgorithm'
-}
newtype HMAC a = HMAC a
{-|
state for 'HMAC' in the 'KeyedHashAlgorithm' instance.
-}
newtype HMACState a = HMACState a

padZero :: Int -> B.ByteString -> B.ByteString
padZero len s = if len > B.length s then B.append s $ B.replicate (len - B.length s) 0 else s

instance HashAlgorithm a => KeyedHashAlgorithm (HMAC a) (HMACState a) where
	implKeyedHashDigestSize = rt hashDigestSize where
		rt :: HashAlgorithm a => Tagged a x -> Tagged (HMAC a) x
		rt = retag
	implKeyedHashName = rt $ ("HMAC-" ++) <$> hashName where
		rt :: HashAlgorithm a => Tagged a x -> Tagged (HMAC a) x
		rt = retag
	implKeyedHashInit key = untag $ tagSelf hashInit >>= \i -> do
		blockSize <- hashBlockSize
		let key' = padZero blockSize $ if B.length key > blockSize then hash' i key else key
		let o_key = B.map (xor 0x5c) key'
		let i_key = B.map (xor 0x36) key'
		return (HMAC $ hashUpdate i o_key, HMACState $ hashUpdate i i_key)
	implKeyedHashUpdate _ (HMACState s) = HMACState . hashUpdate s
	implKeyedHashUpdateLazy _ (HMACState s) = HMACState . hashUpdateLazy s
	implKeyedHashFinalize (HMAC k) (HMACState s) = hashFinalize $ hashUpdate k $ hashFinalize s

{-|
'hmacInit' is the default implementation for 'hashHMAC' and initializes a 'KeyedHash' to calculate
the HMAC for a message with the given @key@.

Example:

> let c = untag (hmacInit (fromString "secretkey") :: Tagged SHA256 KeyedHash) in keyedHashFinalize $ keyedHashUpdate c (fromString "secret message")
-}
hmacInit :: HashAlgorithm a => B.ByteString {- ^ @key@ argument -} -> Tagged a KeyedHash
hmacInit = rt . keyedHashInit where
	rt :: Tagged (HMAC a) x -> Tagged a x
	rt = retag

{-|
Untagged variant of 'hmacInit'; takes a (possible 'undefined') typed 'HashAlgorithm' context as parameter.

Example:

> keyedHashFinalize $ flip keyedHashUpdate (fromString "secret message") $ hmacInit' (undefined :: SHA256) (fromString "secretkey")
-}
hmacInit' :: HashAlgorithm a => a -> B.ByteString -> KeyedHash
hmacInit' = keyedHashInit' . HMAC

{-|
calculate HMAC with a 'HashAlgorithm' for a @key@ and @message@

Example:

> untag (hmac (fromString "secretkey") (fromString "secret message") :: Tagged SHA256 B.ByteString)
-}
hmac :: HashAlgorithm a => B.ByteString {- ^ @key@ argument -} -> B.ByteString {- ^ @message@ argument -} -> Tagged a B.ByteString
hmac key = rt . keyedHash key where
	rt :: Tagged (HMAC a) x -> Tagged a x
	rt = retag

{-|
Untagged variant of 'hmac'; takes a (possible 'undefined') typed 'HashAlgorithm' context as parameter.

Example:

> hmac' (undefined :: SHA256) (fromString "secretkey") (fromString "secret message")
-}
hmac' :: HashAlgorithm a => a -> B.ByteString -> B.ByteString -> B.ByteString
hmac' = keyedHash' . HMAC

{-|
calculate HMAC with a 'HashAlgorithm' for a @key@ and lazy @message@

Example:

> untag (hmacLazy (fromString "secretkey") (fromString "secret message") :: Tagged SHA256 B.ByteString)
-}
hmacLazy :: HashAlgorithm a => B.ByteString {- ^ @key@ argument -} -> L.ByteString {- ^ @message@ argument -} -> Tagged a B.ByteString
hmacLazy key = rt . keyedHashLazy key where
	rt :: Tagged (HMAC a) x -> Tagged a x
	rt = retag

{-|
Untagged variant of 'hmacLazy'; takes a (possible 'undefined') typed 'HashAlgorithm' context as parameter.

Example:

> hmacLazy' (undefined :: SHA256) (fromString "secretkey") (fromString "secret message")
-}
hmacLazy' :: HashAlgorithm a => a -> B.ByteString -> L.ByteString -> B.ByteString
hmacLazy' = keyedHashLazy' . HMAC
