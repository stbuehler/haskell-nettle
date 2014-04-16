{-# LANGUAGE ForeignFunctionInterface, CPP #-}

module Crypto.Nettle.Ciphers.ForeignImports
	( NettleCryptFunc
	, NettleBlockMode
	, NettleGCMMode

	, c_cbc_encrypt
	, c_cbc_decrypt

	, c_cfb_encrypt
	, c_cfb_decrypt

	, c_ctr_crypt

	, c_gcm_ctx_size
	, c_gcm_key_size
	, c_gcm_set_key
	, c_gcm_set_iv
	, c_gcm_update
	, c_gcm_encrypt
	, c_gcm_decrypt
	, c_gcm_digest

	, c_hs_aes_ctx_size
	, c_hs_aes_ctx_encrypt
	, c_hs_aes_ctx_decrypt
	, c_hs_aes_init
	, c_aes_encrypt
	, p_aes_encrypt
	, c_aes_decrypt
	, p_aes_decrypt

	, c_arctwo_ctx_size
	, c_arctwo_set_key
	, c_arctwo_set_key_ekb
	, c_arctwo_encrypt
	, p_arctwo_encrypt
	, c_arctwo_decrypt
	, p_arctwo_decrypt
	, c_arctwo_set_key_gutmann

	, c_blowfish_ctx_size
	, c_blowfish_set_key
	, c_blowfish_encrypt
	, p_blowfish_encrypt
	, c_blowfish_decrypt
	, p_blowfish_decrypt

	, c_hs_camellia_ctx_size
	, c_hs_camellia_ctx_encrypt
	, c_hs_camellia_ctx_decrypt
	, c_hs_camellia_init
	, c_camellia_crypt
	, p_camellia_crypt

	, c_cast128_ctx_size
	, c_cast128_set_key
	, c_cast128_encrypt
	, p_cast128_encrypt
	, c_cast128_decrypt
	, p_cast128_decrypt

	, c_des_ctx_size
	, c_des_set_key
	, c_des_encrypt
	, p_des_encrypt
	, c_des_decrypt
	, p_des_decrypt

	, c_des3_ctx_size
	, c_des3_set_key
	, c_des3_encrypt
	, p_des3_encrypt
	, c_des3_decrypt
	, p_des3_decrypt

	, c_serpent_ctx_size
	, c_serpent_set_key
	, c_serpent_encrypt
	, p_serpent_encrypt
	, c_serpent_decrypt
	, p_serpent_decrypt

	, c_twofish_ctx_size
	, c_twofish_set_key
	, c_twofish_encrypt
	, p_twofish_encrypt
	, c_twofish_decrypt
	, p_twofish_decrypt

	, c_arcfour_ctx_size
	, c_arcfour_set_key
	, c_arcfour_crypt

	, c_salsa20_ctx_size
	, c_salsa20_set_key
	, c_salsa20_set_iv
	, c_salsa20_crypt
	, c_salsa20r12_crypt
	) where

import Nettle.Utils

#ifdef GHCI
-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}
#endif

#include "nettle-ciphers.h"

type NettleCryptFunc = Ptr Word8 -> Word -> Ptr Word8 -> Ptr Word8 -> IO ()
type NettleBlockMode = Ptr Word8 -> FunPtr NettleCryptFunc -> Word -> Ptr Word8 -> Word -> Ptr Word8 -> Ptr Word8 -> IO ()
type NettleGCMMode = Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr NettleCryptFunc -> Word -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "nettle_cbc_encrypt"
	c_cbc_encrypt :: NettleBlockMode
foreign import ccall unsafe "nettle_cbc_decrypt"
	c_cbc_decrypt :: NettleBlockMode

foreign import ccall unsafe "hs_nettle_cfb_encrypt"
	c_cfb_encrypt :: NettleBlockMode
foreign import ccall unsafe "hs_nettle_cfb_decrypt"
	c_cfb_decrypt :: NettleBlockMode

foreign import ccall unsafe "nettle_ctr_crypt"
	c_ctr_crypt :: NettleBlockMode

c_gcm_ctx_size :: Int
c_gcm_ctx_size = #{size struct gcm_ctx}
c_gcm_key_size :: Int
c_gcm_key_size = #{size struct gcm_key}
foreign import ccall unsafe "nettle_gcm_set_key"
	c_gcm_set_key :: Ptr Word8 -> Ptr Word8 -> FunPtr NettleCryptFunc -> IO ()
foreign import ccall unsafe "nettle_gcm_set_iv"
	c_gcm_set_iv :: Ptr Word8 -> Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_gcm_update"
	c_gcm_update :: Ptr Word8 -> Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_gcm_encrypt"
	c_gcm_encrypt :: NettleGCMMode
foreign import ccall unsafe "nettle_gcm_decrypt"
	c_gcm_decrypt :: NettleGCMMode
foreign import ccall unsafe "nettle_gcm_digest"
	c_gcm_digest :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> FunPtr NettleCryptFunc -> Word -> Ptr Word8 -> IO ()

-- block ciphers

c_hs_aes_ctx_size :: Int
c_hs_aes_ctx_size = #{size struct hs_aes_ctx}
c_hs_aes_ctx_encrypt :: Ptr Word8 -> Ptr Word8
c_hs_aes_ctx_encrypt = #ptr struct hs_aes_ctx, encrypt
c_hs_aes_ctx_decrypt :: Ptr Word8 -> Ptr Word8
c_hs_aes_ctx_decrypt = #ptr struct hs_aes_ctx, decrypt
foreign import ccall unsafe "hs_nettle_aes_init"
	c_hs_aes_init :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_aes_encrypt"
	c_aes_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_aes_encrypt"
	p_aes_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_aes_decrypt"
	c_aes_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_aes_decrypt"
	p_aes_decrypt :: FunPtr NettleCryptFunc


c_arctwo_ctx_size :: Int
c_arctwo_ctx_size = #{size struct arctwo_ctx}
foreign import ccall unsafe "nettle_arctwo_set_key"
	c_arctwo_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_arctwo_set_key_ekb"
	c_arctwo_set_key_ekb :: Ptr Word8 -> Word -> Ptr Word8 -> Word -> IO ()
foreign import ccall unsafe "nettle_arctwo_set_key_gutmann"
	c_arctwo_set_key_gutmann :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_arctwo_encrypt"
	c_arctwo_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_arctwo_encrypt"
	p_arctwo_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_arctwo_decrypt"
	c_arctwo_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_arctwo_decrypt"
	p_arctwo_decrypt :: FunPtr NettleCryptFunc

c_blowfish_ctx_size :: Int
c_blowfish_ctx_size = #{size struct blowfish_ctx}
foreign import ccall unsafe "nettle_blowfish_set_key"
	c_blowfish_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_blowfish_encrypt"
	c_blowfish_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_blowfish_encrypt"
	p_blowfish_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_blowfish_decrypt"
	c_blowfish_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_blowfish_decrypt"
	p_blowfish_decrypt :: FunPtr NettleCryptFunc

c_hs_camellia_ctx_size :: Int
c_hs_camellia_ctx_size = #{size struct hs_camellia_ctx}
c_hs_camellia_ctx_encrypt :: Ptr Word8 -> Ptr Word8
c_hs_camellia_ctx_encrypt = #ptr struct hs_camellia_ctx, encrypt
c_hs_camellia_ctx_decrypt :: Ptr Word8 -> Ptr Word8
c_hs_camellia_ctx_decrypt = #ptr struct hs_camellia_ctx, decrypt
foreign import ccall unsafe "hs_nettle_camellia_init"
	c_hs_camellia_init :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_camellia_crypt"
	c_camellia_crypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_camellia_crypt"
	p_camellia_crypt :: FunPtr NettleCryptFunc

c_cast128_ctx_size :: Int
c_cast128_ctx_size = #{size struct cast128_ctx}
foreign import ccall unsafe "nettle_cast128_set_key"
	c_cast128_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cast128_encrypt"
	c_cast128_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_cast128_encrypt"
	p_cast128_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_cast128_decrypt"
	c_cast128_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_cast128_decrypt"
	p_cast128_decrypt :: FunPtr NettleCryptFunc

c_des_ctx_size :: Int
c_des_ctx_size = #{size struct des_ctx}
foreign import ccall unsafe "nettle/des.h nettle_des_set_key"
	c_des_set_key :: Ptr Word8 -> Ptr Word8 -> IO () -- ignore return value
foreign import ccall unsafe "nettle/des.h nettle_des_encrypt"
	c_des_encrypt :: NettleCryptFunc
foreign import ccall unsafe "nettle/des.h &nettle_des_encrypt"
	p_des_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle/des.h nettle_des_decrypt"
	c_des_decrypt :: NettleCryptFunc
foreign import ccall unsafe "nettle/des.h &nettle_des_decrypt"
	p_des_decrypt :: FunPtr NettleCryptFunc

c_des3_ctx_size :: Int
c_des3_ctx_size = #{size struct des3_ctx}
foreign import ccall unsafe "nettle/des.h nettle_des3_set_key"
	c_des3_set_key :: Ptr Word8 -> Ptr Word8 -> IO () -- ignore return value
foreign import ccall unsafe "nettle/des.h nettle_des3_encrypt"
	c_des3_encrypt :: NettleCryptFunc
foreign import ccall unsafe "nettle/des.h &nettle_des3_encrypt"
	p_des3_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle/des.h nettle_des3_decrypt"
	c_des3_decrypt :: NettleCryptFunc
foreign import ccall unsafe "nettle/des.h &nettle_des3_decrypt"
	p_des3_decrypt :: FunPtr NettleCryptFunc

c_serpent_ctx_size :: Int
c_serpent_ctx_size = #{size struct serpent_ctx}
foreign import ccall unsafe "nettle_serpent_set_key"
	c_serpent_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_serpent_encrypt"
	c_serpent_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_serpent_encrypt"
	p_serpent_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_serpent_decrypt"
	c_serpent_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_serpent_decrypt"
	p_serpent_decrypt :: FunPtr NettleCryptFunc

c_twofish_ctx_size :: Int
c_twofish_ctx_size = #{size struct twofish_ctx}
foreign import ccall unsafe "nettle_twofish_set_key"
	c_twofish_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_twofish_encrypt"
	c_twofish_encrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_twofish_encrypt"
	p_twofish_encrypt :: FunPtr NettleCryptFunc
foreign import ccall unsafe "nettle_twofish_decrypt"
	c_twofish_decrypt :: NettleCryptFunc
foreign import ccall unsafe "&nettle_twofish_decrypt"
	p_twofish_decrypt :: FunPtr NettleCryptFunc


-- stream ciphers
c_arcfour_ctx_size :: Int
c_arcfour_ctx_size = #{size struct arcfour_ctx}
foreign import ccall unsafe "nettle_arcfour_set_key"
	c_arcfour_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_arcfour_crypt"
	c_arcfour_crypt :: NettleCryptFunc

c_salsa20_ctx_size :: Int
c_salsa20_ctx_size = #{size struct salsa20_ctx}
foreign import ccall unsafe "nettle_salsa20_set_key"
	c_salsa20_set_key :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_salsa20_set_iv"
	c_salsa20_set_iv :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_salsa20_crypt"
	c_salsa20_crypt :: NettleCryptFunc
foreign import ccall unsafe "nettle_salsa20r12_crypt"
	c_salsa20r12_crypt :: NettleCryptFunc




