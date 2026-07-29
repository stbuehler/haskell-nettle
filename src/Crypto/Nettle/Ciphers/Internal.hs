{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE MultiParamTypeClasses, FlexibleInstances, FlexibleContexts, LambdaCase #-}

module Crypto.Nettle.Ciphers.Internal
	( NettleCipher(..)
	, NettleBlockCipher(..)
	, NettleStreamCipher(..)
	, NettleBlockedStreamCipher(..)
	, NettleAeadModeImpl(..)
	, NettleGCM
	, nettle_cipherInit
	, nettle_cipherInit'
	, nettle_ecbEncrypt
	, nettle_ecbDecrypt
	, nettle_cbcEncrypt
	, nettle_cbcDecrypt
	, nettle_cfbEncrypt
	, nettle_cfbDecrypt
	, nettle_ctrCombine
	, nettle_streamCombine
	, nettle_streamSetNonce
	, nettle_blockedStreamCombine
	, nettle_blockedStreamSetNonce
	, nettle_gcm_aeadInit
	, nettle_gcm_aeadStateAppendHeader
	, nettle_gcm_aeadStateEncrypt
	, nettle_gcm_aeadStateDecrypt
	, nettle_gcm_aeadStateFinalize
	) where

import Crypto.Cipher.Types as CCT
import Crypto.Error

import Data.Tagged
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

import Nettle.Utils
import Crypto.Nettle.Ciphers.ForeignImports

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

class NettleCipher c where
	-- | pointer to new context, key length, (const) key pointer
	nc_cipherInit    :: Tagged c (Ptr Word8 -> Word -> Ptr Word8 -> IO())
	nc_cipherName    :: Tagged c String
	nc_cipherKeySize :: Tagged c CCT.KeySizeSpecifier
	nc_ctx_size      :: Tagged c Int
	nc_ctx           :: c -> BA.ScrubbedBytes
	nc_Ctx           :: BA.ScrubbedBytes -> c
class NettleCipher c => NettleBlockCipher c where
	nbc_blockSize          :: Tagged c Int
	nbc_encrypt_ctx_offset :: Tagged c (Ptr Word8 -> Ptr Word8)
	nbc_encrypt_ctx_offset = Tagged id
	nbc_decrypt_ctx_offset :: Tagged c (Ptr Word8 -> Ptr Word8)
	nbc_decrypt_ctx_offset = Tagged id
	nbc_ecb_encrypt        :: Tagged c NettleCryptFunc
	nbc_ecb_decrypt        :: Tagged c NettleCryptFunc
	nbc_fun_encrypt        :: Tagged c (FunPtr NettleCryptFunc)
	nbc_fun_decrypt        :: Tagged c (FunPtr NettleCryptFunc)
class NettleCipher c => NettleStreamCipher c where
	nsc_streamCombine      :: Tagged c NettleCryptFunc
	nsc_nonceSize          :: Tagged c CCT.KeySizeSpecifier
	nsc_nonceSize          = Tagged $ CCT.KeySizeEnum []
	nsc_setNonce           :: Tagged c (Maybe (Ptr Word8 -> Word -> Ptr Word8 -> IO ()))
	nsc_setNonce           = Tagged Nothing

-- stream cipher based on generating (large) blocks to XOR with input,
-- but don't keep incomplete blocks in the state, so we have to do that here
class NettleCipher c => NettleBlockedStreamCipher c where
	nbsc_blockSize          :: Tagged c Int
	-- set new incomplete state
	nbsc_IncompleteState    :: c -> B.ByteString -> c
	nbsc_incompleteState    :: c -> B.ByteString
	nbsc_streamCombine      :: Tagged c NettleCryptFunc
	nbsc_nonceSize          :: Tagged c CCT.KeySizeSpecifier
	nbsc_nonceSize          = Tagged $ CCT.KeySizeEnum []
	nbsc_setNonce           :: Tagged c (Maybe (Ptr Word8 -> Word -> Ptr Word8 -> IO ()))
	nbsc_setNonce           = Tagged Nothing

class NettleAeadModeImpl c state where
	nettle_aead_mode_impl :: c -> CCT.AEADModeImpl state

nettle_cipherInit :: (NettleCipher c, BA.ByteArray key) => key -> CryptoFailable c
nettle_cipherInit k = let ctx = nettle_cipherInit' (nc_cipherInit `witness` (throwCryptoError ctx)) k in ctx

nettle_cipherInit' :: (NettleCipher c, BA.ByteArray key) => (Ptr Word8 -> Word -> Ptr Word8 -> IO()) -> key -> CryptoFailable c
nettle_cipherInit' f k = let ctx = (\case {
		  Nothing -> CryptoPassed $ nc_Ctx $ key_init f (nc_ctx_size `witness` (throwCryptoError ctx)) k
		; Just e -> CryptoFailed e
		}) (validate_keySize (nc_cipherKeySize `witness` (throwCryptoError ctx)) k)
	in ctx

validate_keySize :: (BA.ByteArrayAccess key) => CCT.KeySizeSpecifier -> key -> Maybe CryptoError
validate_keySize spec k = case spec of
	CCT.KeySizeRange bot top -> if bot <= BA.length k && BA.length k <= top	then Nothing else Just CryptoError_KeySizeInvalid
	CCT.KeySizeEnum list     -> if (BA.length k) `elem` list		then Nothing else Just CryptoError_KeySizeInvalid
	CCT.KeySizeFixed f       -> if BA.length k == f				then Nothing else Just CryptoError_KeySizeInvalid

assert_blockSize :: (NettleBlockCipher c, BA.ByteArrayAccess ba) => c -> ba -> a -> a
assert_blockSize c src result = if 0 /= BA.length src `mod` (nbc_blockSize `witness` c) then error "input not a multiple of blockSize" else result

nettle_ecbEncrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> bin -> bout
nettle_ecbEncrypt c    src = assert_blockSize c src $ c_run_crypt   (nbc_encrypt_ctx_offset `witness` c)               (nbc_ecb_encrypt `witness` c) (nc_ctx c) src
nettle_ecbDecrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> bin -> bout
nettle_ecbDecrypt c    src = assert_blockSize c src $ c_run_crypt   (nbc_decrypt_ctx_offset `witness` c)               (nbc_ecb_decrypt `witness` c) (nc_ctx c) src
nettle_cbcEncrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> IV c -> bin -> bout
nettle_cbcEncrypt c iv src = assert_blockSize c src $ blockmode_run (nbc_encrypt_ctx_offset `witness` c) c_cbc_encrypt (nbc_fun_encrypt `witness` c) (nc_ctx c) iv src
nettle_cbcDecrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> IV c -> bin -> bout
nettle_cbcDecrypt c iv src = assert_blockSize c src $ blockmode_run (nbc_decrypt_ctx_offset `witness` c) c_cbc_decrypt (nbc_fun_decrypt `witness` c) (nc_ctx c) iv src
nettle_cfbEncrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> IV c -> bin -> bout
nettle_cfbEncrypt c iv src = assert_blockSize c src $ blockmode_run (nbc_encrypt_ctx_offset `witness` c) c_cfb_encrypt (nbc_fun_encrypt `witness` c) (nc_ctx c) iv src
nettle_cfbDecrypt :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> IV c -> bin -> bout
nettle_cfbDecrypt c iv src = assert_blockSize c src $ blockmode_run (nbc_encrypt_ctx_offset `witness` c) c_cfb_decrypt (nbc_fun_encrypt `witness` c) (nc_ctx c) iv src
nettle_ctrCombine :: (CCT.BlockCipher c, NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> IV c -> bin -> bout
nettle_ctrCombine c        =                          blockmode_run (nbc_encrypt_ctx_offset `witness` c) c_ctr_crypt   (nbc_fun_encrypt `witness` c) (nc_ctx c)

nettle_streamCombine :: (NettleStreamCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> bin -> (bout, c)
nettle_streamCombine c indata = let (r, c') = stream_crypt (nsc_streamCombine `witness` c) (nc_ctx c) indata in (r, nc_Ctx c')
nettle_streamSetNonce :: NettleStreamCipher c => c -> B.ByteString -> Maybe c
nettle_streamSetNonce c nonce = case nsc_setNonce `witness` c of
	Nothing -> Nothing
	Just setnonce -> let ctx' = copyScrubbedBytes (nc_ctx c) in
		unsafeDupablePerformIO $
		BA.withByteArray ctx' $ \ctxptr ->
		withByteStringPtr nonce $ \noncelen nonceptr ->
		setnonce ctxptr noncelen nonceptr >>
		return (Just $ nc_Ctx ctx')

nettle_blockedStreamCombine :: (NettleBlockedStreamCipher c, BA.ByteArray bin, BA.ByteArray bout) => c -> bin -> (bout, c)
nettle_blockedStreamCombine c indata = if BA.length indata == 0 then (BA.convert indata, c) else
	let inc = nbsc_incompleteState c; blocksiz = nbsc_blockSize `witness` c in
	if B.length inc /= 0
		then let
			-- first xor remaining block, then combine the rest
			(i1, i2) = BA.splitAt (B.length inc) indata
			(inc1, inc2) = B.splitAt (BA.length indata) inc
			r1 = BA.xor i1 inc1
			c' = if B.length inc2 == 0 then nc_Ctx $ nc_ctx c else nbsc_IncompleteState c inc2
			(r, c'') = nettle_blockedStreamCombine c' i2
			in (BA.append r1 r, c'')
		else if BA.length indata `mod` blocksiz /= 0
			then let
				padding = BA.replicate (blocksiz - (BA.length indata `mod` blocksiz)) 0
				(r', c') = stream_crypt (nbsc_streamCombine `witness` c) (nc_ctx c) (BA.append indata padding)
				(r, inc') = BA.splitAt (BA.length indata) r'
				in (r, nbsc_IncompleteState (nc_Ctx c') (BA.convert inc'))
			else
				let (r, c') = stream_crypt (nbsc_streamCombine `witness` c) (nc_ctx c) indata in (r, nc_Ctx c')
nettle_blockedStreamSetNonce :: NettleBlockedStreamCipher c => c -> B.ByteString -> Maybe c
nettle_blockedStreamSetNonce c nonce = case nbsc_setNonce `witness` c of
	Nothing -> Nothing
	Just setnonce -> let ctx' = copyScrubbedBytes (nc_ctx c) in
		unsafeDupablePerformIO $
		BA.withByteArray ctx' $ \ctxptr ->
		withByteStringPtr nonce $ \noncelen nonceptr ->
		setnonce ctxptr noncelen nonceptr >>
		return (Just $ nc_Ctx ctx')


nettle_gcm_aeadInit              :: (NettleBlockCipher c, NettleAeadModeImpl c NettleGCM, BA.ByteArrayAccess iv) => c -> iv -> CryptoFailable (CCT.AEAD c)
nettle_gcm_aeadInit          c  iv = if nbc_blockSize `witness` c == 16 then CryptoPassed $ CCT.AEAD {CCT.aeadModeImpl = nettle_aead_mode_impl c, CCT.aeadState = gcm_init (nbc_encrypt_ctx_offset `witness` c) (nbc_fun_encrypt `witness` c) (nc_ctx c) iv} else CryptoFailed CryptoError_AEADModeNotSupported
nettle_gcm_aeadStateAppendHeader :: BA.ByteArrayAccess ba => t -> NettleGCM -> ba -> NettleGCM
nettle_gcm_aeadStateAppendHeader _ = gcm_update
nettle_gcm_aeadStateEncrypt      :: (NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> NettleGCM -> bin -> (bout, NettleGCM)
nettle_gcm_aeadStateEncrypt      c = gcm_crypt c_gcm_encrypt (nbc_encrypt_ctx_offset `witness` c) (nbc_fun_encrypt `witness` c) (nc_ctx c)
nettle_gcm_aeadStateDecrypt      :: (NettleBlockCipher c, BA.ByteArrayAccess bin, BA.ByteArray bout) => c -> NettleGCM -> bin -> (bout, NettleGCM)
nettle_gcm_aeadStateDecrypt      c = gcm_crypt c_gcm_decrypt (nbc_encrypt_ctx_offset `witness` c) (nbc_fun_encrypt `witness` c) (nc_ctx c)
nettle_gcm_aeadStateFinalize     :: NettleBlockCipher c => c -> NettleGCM -> Int -> CCT.AuthTag
nettle_gcm_aeadStateFinalize     c = gcm_digest              (nbc_encrypt_ctx_offset `witness` c) (nbc_fun_encrypt `witness` c) (nc_ctx c)



key_init
	:: BA.ByteArrayAccess k
	=> (Ptr Word8 -> Word -> Ptr Word8 -> IO ())
	-> Int -> k -> BA.ScrubbedBytes
key_init initfun size k = BA.unsafeCreate size $ \ctxptr ->
	BA.withByteArray k $ \kptr -> initfun ctxptr (fromIntegral $ BA.length k) kptr

-- run encryption/decryption with same length for in and output
c_run_crypt
	:: (BA.ByteArrayAccess bin,
	    BA.ByteArray bout)
	=> (Ptr Word8 -> Ptr Word8)
	-> NettleCryptFunc
	-> BA.ScrubbedBytes -> bin -> bout
c_run_crypt ctxoffset cfun ctx indata = unsafeDupablePerformIO $ BA.withByteArray ctx $ \ctxptr ->
	BA.withByteArray indata $ \indataptr ->
	BA.create (BA.length indata) $ \outptr ->
	cfun (ctxoffset ctxptr) (fromIntegral $ BA.length indata) outptr indataptr

blockmode_run
	:: (BA.ByteArrayAccess iv,
	    BA.ByteArrayAccess bin,
	    BA.ByteArray bout)
	=> (Ptr Word8 -> Ptr Word8)
	-> NettleBlockMode
	-> FunPtr NettleCryptFunc
	-> BA.ScrubbedBytes -> iv -> bin -> bout
blockmode_run ctxoffset mode crypt ctx iv indata = let iv' = copyAndConvertToScrubbedBytes iv in -- copy IV, may get modified
	unsafeDupablePerformIO $ BA.withByteArray ctx $ \ctxptr ->
	BA.withByteArray indata $ \indataptr ->
	BA.withByteArray iv' $ \ivptr ->
	BA.create (BA.length indata) $ \outptr ->
	mode (ctxoffset ctxptr) crypt (fromIntegral $ BA.length iv') ivptr (fromIntegral $ BA.length indata) outptr indataptr

data NettleGCM = NettleGCM !BA.ScrubbedBytes !BA.ScrubbedBytes

gcm_init
	:: BA.ByteArrayAccess iv
	=> (Ptr Word8 -> Ptr Word8)
	-> FunPtr NettleCryptFunc
	-> BA.ScrubbedBytes -> iv -> NettleGCM
gcm_init encctxoffset encrypt encctx iv = unsafeDupablePerformIO $
	BA.withByteArray iv $ \ivptr ->
	BA.withByteArray encctx $ \encctxptr -> do
	h <- BA.create c_gcm_key_size $ \hptr ->
		c_gcm_set_key hptr (encctxoffset encctxptr) encrypt
	BA.withByteArray h $ \hptr -> do
	    ctx <- BA.create c_gcm_ctx_size $ \ctxptr ->
		c_gcm_set_iv ctxptr hptr (fromIntegral $ BA.length iv) ivptr
	    return (NettleGCM ctx h)

-- independent of cipher
gcm_update
	:: BA.ByteArrayAccess ba => NettleGCM -> ba -> NettleGCM
gcm_update (NettleGCM ctx h) indata = let ctx' = copyScrubbedBytes ctx in
	unsafeDupablePerformIO $
	BA.withByteArray ctx' $ \ctxptr ->
	BA.withByteArray h $ \hptr ->
	BA.withByteArray indata $ \indataptr ->
	c_gcm_update ctxptr hptr (fromIntegral $ BA.length indata) indataptr >>
	return (NettleGCM ctx' h)

gcm_crypt
	:: (BA.ByteArrayAccess bin,
	    BA.ByteArray bout)
	=> NettleGCMMode
	-> (Ptr Word8 -> Ptr Word8)
	-> FunPtr NettleCryptFunc
	-> BA.ScrubbedBytes -> NettleGCM -> bin -> (bout, NettleGCM)
gcm_crypt mode encctxoffset encrypt encctx (NettleGCM ctx h) indata = let ctx' = copyScrubbedBytes ctx in
	unsafeDupablePerformIO $
	BA.withByteArray ctx' $ \ctxptr ->
	BA.withByteArray h $ \hptr ->
	BA.withByteArray encctx $ \encctxptr ->
	BA.withByteArray indata $ \indataptr -> do
	outdata <- BA.create (BA.length indata) $ \outptr ->
		mode ctxptr hptr (encctxoffset encctxptr) encrypt (fromIntegral $ BA.length indata) outptr indataptr
	return (outdata, NettleGCM ctx' h)

gcm_digest
	:: (Ptr Word8 -> Ptr Word8)
	-> FunPtr NettleCryptFunc
	-> BA.ScrubbedBytes -> NettleGCM -> Int -> CCT.AuthTag
gcm_digest encctxoffset encrypt encctx (NettleGCM ctx h) taglen = let ctx' = copyScrubbedBytes ctx in
	unsafeDupablePerformIO $
	BA.withByteArray ctx' $ \ctxptr ->
	BA.withByteArray h $ \hptr ->
	BA.withByteArray encctx $ \encctxptr -> do
	tag <- BA.create (fromIntegral taglen) $ \tagptr ->
		c_gcm_digest ctxptr hptr (encctxoffset encctxptr) encrypt (fromIntegral taglen) tagptr
	return $ CCT.AuthTag tag

stream_crypt
	:: (BA.ByteArrayAccess bin,
	    BA.ByteArray bout)
	=> NettleCryptFunc
	-> BA.ScrubbedBytes -> bin -> (bout, BA.ScrubbedBytes)
stream_crypt crypt ctx indata = let ctx' = copyScrubbedBytes ctx in
	unsafeDupablePerformIO $
	BA.withByteArray ctx' $ \ctxptr ->
	BA.withByteArray indata $ \indataptr -> do
	outdata <- BA.create (BA.length indata) $ \outptr ->
		crypt ctxptr (fromIntegral $ BA.length indata) outptr indataptr
	return (outdata, ctx')
