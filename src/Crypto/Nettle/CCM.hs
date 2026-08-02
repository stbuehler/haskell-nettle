{-# LANGUAGE MultiParamTypeClasses, FlexibleInstances #-}
-----------------------------------------------------------------------------
-- |
-- Module      :  Crypto.Nettle.CCM
-- Copyright   :  (c) 2013 Stefan Bühler
-- License     :  MIT-style (see the file COPYING)
-- 
-- Maintainer  :  stbuehler@web.de
-- Stability   :  experimental
-- Portability :  portable
--
-- (This is not a binding to nettle; it is implemented in pure haskell)
--
-- This module adds CCM support to all 128-bit block ciphers:
--
-- @aeadInit AEAD_CCM = ccmInitTLS@
--
-- CCM uses 2 parameters t and q: t is the tag length (2,4,6,8,10,12,14,16) and q (2..8) is the
-- length in bytes that the length of the message is stored in (and the length of the
-- counter variable).
-- Maximum message length is @2^(8*q) - 1@.
--
-- CCM requires a nonce of length (15 - q). TLS uses CCM with @t = 16@ and @q = 3@,
-- and a nonce length of 12 (the first 4 bytes are fixed from the handshake, the other 8
-- usually represent the sequence counter).
--
-- CCM encrypts with a CTR mode, the start IV is based on the (t,q,nonce) parameters;
-- the tag is encrypted with counter value = 0, then the message follows.
--
-- Calculating the tag needs the message length first - so this implementation needs
-- to gather all data before calculating it.
--
-- In RFC 3610 @t@ is called @M@, and @q@ is called @L@.
-----------------------------------------------------------------------------

module Crypto.Nettle.CCM
	( ccmInit
	, ccmInitTLS
	) where

import qualified Crypto.Cipher.Types as CCT
import Crypto.Error
import qualified Data.ByteArray as BA
import Data.Maybe (fromJust)

import Crypto.Nettle.Ciphers.Internal
import Nettle.Utils

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

-- ccm needs a 128-bit block cipher

data CCM cipher message nonce
	= CCM_Header (Int, Int, nonce) message
	| CCM_Enc (Int, Int, nonce) message (CCT.IV cipher) message
	| CCM_Dec (Int, Int, nonce) message (CCT.IV cipher) message

{-|
Start a CCM encryption with specified tag length @t@, length @q@ of the message length field and a @15-q@ bytes long @nonce@.
Fails if any parameter is invalid or the block cipher doesn't use a 16-byte 'blockSize'.
-}
ccmInit
	:: (CCT.BlockCipher cipher, BA.ByteArrayAccess iv)
	=> Int    -- ^ tag length @t@
	-> Int    -- ^ length @q@ of the message length field
	-> cipher -- ^ cipher initialized with key
	-> iv     -- ^ @nonce@ with length @15-q@
	-> CryptoFailable (CCT.AEAD cipher )
ccmInit t q cipher nonce = ccm_init t q cipher nonce >>= \state -> (CryptoPassed $ CCT.AEAD {CCT.aeadModeImpl = nettle_aead_mode_impl cipher, CCT.aeadState = state})

ccm_init :: (CCT.BlockCipher cipher, BA.ByteArrayAccess iv) => Int -> Int -> cipher -> iv -> CryptoFailable (CCM cipher BA.ScrubbedBytes BA.ScrubbedBytes)
ccm_init t q cipher nonce = if valid then CryptoPassed $ CCM_Header (t, q, copyAndConvertToScrubbedBytes nonce) BA.empty else CryptoFailed reason
	where
	valid = valid_cipher && valid_t && valid_q && valid_nonce
	valid_cipher = CCT.blockSize cipher == 16
	valid_t = t >= 4 && t <= 16 && even t
	valid_q = q >= 2 && q <= 8
	nonce_len = 15 - q
	valid_nonce = BA.length nonce == fromIntegral nonce_len
	reason = if not valid_cipher then CryptoError_KeySizeInvalid
		else if not valid_t then CryptoError_AuthenticationTagSizeInvalid
		else if not valid_nonce then CryptoError_IvSizeInvalid
		else CryptoError_AEADModeNotSupported

{-|
Start a CCM encryption with specified tag length @t = 16@, length @q = 3@ for the message length field and a @8@ bytes long @nonce@.
Fails if any parameter is invalid or the block cipher doesn't use a 16-byte 'blockSize'.
This are the parameters used for TLS.
-}
ccmInitTLS
	:: (CCT.BlockCipher cipher, BA.ByteArrayAccess iv)
	=> cipher -- ^ cipher initialized with key
	-> iv     -- ^ 8 byte @nonce@
	-> CryptoFailable (CCT.AEAD cipher)
ccmInitTLS = ccmInit 16 3


ccm_encodeAdditionalLength :: BA.ByteArray ba => ba -> ba
ccm_encodeAdditionalLength s = BA.append (encLen $ BA.length s) s where
	encLen n
		| n == 0                       = BA.empty
		| n < (2^(16::Int)-2^(8::Int)) = BA.pack $ netEncode 2 n
		| n < (2^(32::Int))            = BA.pack (0xff:0xfe:netEncode 4 n)
		| otherwise                    = BA.pack (0xff:0xff:netEncode 8 n)

pad_zero :: BA.ByteArray ba => Int -> ba -> ba
pad_zero l s = BA.append s $ BA.replicate (l - 1 - (BA.length s - 1) `mod` l) 0

_makeIV :: (CCT.BlockCipher cipher, BA.ByteArrayAccess ba) => ba -> CCT.IV cipher
_makeIV = fromJust . CCT.makeIV

ccm_start_iv :: (CCT.BlockCipher cipher, BA.ByteArray bn) => (Int, Int, bn) -> CCT.IV cipher
ccm_start_iv (_, q, nonce) = _makeIV $ concatToScrubbedBytes [BA.singleton $ fromIntegral $ q - 1, nonce, BA.replicate (q - 1) 0, BA.singleton 1]

ccm_tag_iv :: (CCT.BlockCipher cipher, BA.ByteArray bn) => (Int, Int, bn) -> CCT.IV cipher
ccm_tag_iv (_, q, nonce) = _makeIV $ concatToScrubbedBytes [BA.singleton $ fromIntegral $ q - 1, nonce, BA.replicate q 0]

ccm_crypt :: (CCT.BlockCipher cipher, BA.ByteArray ba) => cipher -> CCT.IV cipher -> ba -> (ba, CCT.IV cipher)
ccm_crypt key iv src = let
	blocks = (BA.length src + 15) `div` 16
	dst = CCT.ctrCombine key iv src
	iv' = CCT.ivAdd iv blocks
	in (dst, iv')

ccm_tag :: (CCT.BlockCipher cipher, BA.ByteArray ba, BA.ByteArray bn) => cipher -> (Int, Int, bn) -> ba -> ba -> Int -> CCT.AuthTag
ccm_tag key (t, q, nonce) header msg taglen = let
	-- 64*(header != "") + 8*M' + L'
	auth_flags = (if BA.length header > 0 then 64 else 0) + 4*(fromIntegral t - 2) + (fromIntegral q - 1)
	b0 = BA.concat [BA.singleton auth_flags, nonce, BA.pack $ netEncode q $ BA.length msg]
	blocks = BA.concat [b0, pad_zero 16 $ ccm_encodeAdditionalLength header, pad_zero 16 msg]
	tag = fst $ ccm_crypt key (ccm_tag_iv (t, q, nonce)) $ BA.drop (BA.length blocks - 16) $ CCT.cbcEncrypt key CCT.nullIV blocks
	in CCT.AuthTag $ BA.take taglen tag


nettle_ccm_aeadImplAppendHeader :: (CCT.BlockCipher cipher, BA.ByteArrayAccess msg, BA.ByteArray ba) => cipher -> (CCM cipher ba ba) -> msg -> (CCM cipher ba ba)
nettle_ccm_aeadImplAppendHeader _ (CCM_Header (t, q, nonce) header) src = CCM_Header (t, q, nonce) $ BA.append header (BA.convert src)
nettle_ccm_aeadImplAppendHeader _ _ _ = error "can't aeadStateAppendHeader anymore, already have real data"

nettle_ccm_aeadImplEncrypt :: (CCT.BlockCipher cipher, BA.ByteArray msg, BA.ByteArray ba) => cipher -> (CCM cipher ba ba) -> msg -> (msg, (CCM cipher ba ba))
nettle_ccm_aeadImplEncrypt key (CCM_Header (t, q, nonce) header) src = nettle_ccm_aeadImplEncrypt key (CCM_Enc (t, q, nonce) header iv BA.empty) src
			where iv = ccm_start_iv (t, q, nonce)
nettle_ccm_aeadImplEncrypt key (CCM_Enc (t, q, nonce) header iv msg) src = let
			(dst, iv') = ccm_crypt key iv src
			in (dst, CCM_Enc (t, q, nonce) header iv' $ BA.append msg (BA.convert src))
nettle_ccm_aeadImplEncrypt _ _ _ = error "can't aeadStateEncrypt anymore, already is in decrypt mode"

nettle_ccm_aeadImplDecrypt :: (CCT.BlockCipher cipher, BA.ByteArray msg, BA.ByteArray ba) => cipher -> (CCM cipher ba ba) -> msg -> (msg, (CCM cipher ba ba))
nettle_ccm_aeadImplDecrypt key (CCM_Header (t, q, nonce) header) src = nettle_ccm_aeadImplDecrypt key (CCM_Dec (t, q, nonce) header iv BA.empty) src
			where iv = ccm_start_iv (t, q, nonce)
nettle_ccm_aeadImplDecrypt key (CCM_Dec (t, q, nonce) header iv msg) src = let
			(dst, iv') = ccm_crypt key iv src
			in (dst, CCM_Enc (t, q, nonce) header iv' $ BA.append msg (BA.convert dst))
nettle_ccm_aeadImplDecrypt _ _ _ = error "can't aeadStateDecrypt anymore, already is in encrypt mode"

nettle_ccm_aeadImplFinalize :: (CCT.BlockCipher cipher, BA.ByteArray msg, BA.ByteArray nonce) => cipher -> (CCM cipher msg nonce) -> Int -> CCT.AuthTag
nettle_ccm_aeadImplFinalize key (CCM_Header (t, q, nonce) header      ) taglen = ccm_tag key (t, q, nonce) header BA.empty taglen
nettle_ccm_aeadImplFinalize key (CCM_Enc    (t, q, nonce) header _ msg) taglen = ccm_tag key (t, q, nonce) header msg      taglen
nettle_ccm_aeadImplFinalize key (CCM_Dec    (t, q, nonce) header _ msg) taglen = ccm_tag key (t, q, nonce) header msg      taglen

instance (CCT.BlockCipher cipher, BA.ByteArray ba) => NettleAeadModeImpl cipher (CCM cipher ba ba) where
	nettle_aead_mode_impl c = CCT.AEADModeImpl {
		CCT.aeadImplAppendHeader = nettle_ccm_aeadImplAppendHeader c
		, CCT.aeadImplEncrypt = nettle_ccm_aeadImplEncrypt c
		, CCT.aeadImplDecrypt = nettle_ccm_aeadImplDecrypt c
		, CCT.aeadImplFinalize = nettle_ccm_aeadImplFinalize c
	}