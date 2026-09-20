{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ForeignFunctionInterface, CPP #-}

module Crypto.Nettle.Hash.ForeignImports
	( NettleHashInit
	, NettleHashUpdate
	, NettleHashDigest

	, callNettleHashDigest

	, c_sha256_ctx_size
	, c_sha256_digest_size
	, c_sha256_block_size
	, c_sha256_init
	, c_sha256_update
	, c_sha256_digest

	, c_sha224_ctx_size
	, c_sha224_digest_size
	, c_sha224_block_size
	, c_sha224_init
	, c_sha224_update
	, c_sha224_digest

	, c_sha512_ctx_size
	, c_sha512_digest_size
	, c_sha512_block_size
	, c_sha512_init
	, c_sha512_update
	, c_sha512_digest

	, c_sha384_ctx_size
	, c_sha384_digest_size
	, c_sha384_block_size
	, c_sha384_init
	, c_sha384_update
	, c_sha384_digest

#if (NETTLE_VERSION_MAJOR > 3)
        , c_sha3_init
#endif

	, c_sha3_224_ctx_size
	, c_sha3_224_digest_size
	, c_sha3_224_block_size
	, c_sha3_224_init
	, c_sha3_224_update
	, c_sha3_224_digest

	, c_sha3_256_ctx_size
	, c_sha3_256_digest_size
	, c_sha3_256_block_size
	, c_sha3_256_init
	, c_sha3_256_update
	, c_sha3_256_digest

	, c_sha3_384_ctx_size
	, c_sha3_384_digest_size
	, c_sha3_384_block_size
	, c_sha3_384_init
	, c_sha3_384_update
	, c_sha3_384_digest

	, c_sha3_512_ctx_size
	, c_sha3_512_digest_size
	, c_sha3_512_block_size
	, c_sha3_512_init
	, c_sha3_512_update
	, c_sha3_512_digest

	, c_sm3_ctx_size
	, c_sm3_digest_size
	, c_sm3_block_size
	, c_sm3_init
	, c_sm3_update
	, c_sm3_digest

	, c_streebog512_ctx_size
	, c_streebog512_digest_size
	, c_streebog512_block_size
	, c_streebog512_init
	, c_streebog512_update
	, c_streebog512_digest

	, c_streebog256_ctx_size
	, c_streebog256_digest_size
	, c_streebog256_block_size
	, c_streebog256_init
	, c_streebog256_update
	, c_streebog256_digest

#if (NETTLE_VERSION_MAJOR > 3 || (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 10))
	, c_sha3_128_ctx_size
	, c_sha3_128_init
	, c_sha3_128_update
	, c_sha3_128_shake
#endif
	, c_sha3_256_shake

	, c_md5_ctx_size
	, c_md5_digest_size
	, c_md5_block_size
	, c_md5_init
	, c_md5_update
	, c_md5_digest

	, c_md2_ctx_size
	, c_md2_digest_size
	, c_md2_block_size
	, c_md2_init
	, c_md2_update
	, c_md2_digest

	, c_md4_ctx_size
	, c_md4_digest_size
	, c_md4_block_size
	, c_md4_init
	, c_md4_update
	, c_md4_digest

	, c_ripemd160_ctx_size
	, c_ripemd160_digest_size
	, c_ripemd160_block_size
	, c_ripemd160_init
	, c_ripemd160_update
	, c_ripemd160_digest

	, c_sha1_ctx_size
	, c_sha1_digest_size
	, c_sha1_block_size
	, c_sha1_init
	, c_sha1_update
	, c_sha1_digest

	, c_gosthash94_ctx_size
	, c_gosthash94_digest_size
	, c_gosthash94_block_size
	, c_gosthash94_init
	, c_gosthash94_update
	, c_gosthash94_digest

	, c_umac32_ctx_size
	, c_umac32_digest_size
	, c_umac32_set_key
	, c_umac32_set_nonce
	, c_umac32_update
	, c_umac32_digest

	, c_umac64_ctx_size
	, c_umac64_digest_size
	, c_umac64_set_key
	, c_umac64_set_nonce
	, c_umac64_update
	, c_umac64_digest

	, c_umac96_ctx_size
	, c_umac96_digest_size
	, c_umac96_set_key
	, c_umac96_set_nonce
	, c_umac96_update
	, c_umac96_digest

	, c_umac128_ctx_size
	, c_umac128_digest_size
	, c_umac128_set_key
	, c_umac128_set_nonce
	, c_umac128_update
	, c_umac128_digest

	, c_cmac_aes128_ctx_size
	, c_cmac_aes128_set_key
	, c_cmac_aes128_update
	, c_cmac_aes128_digest

	, c_cmac_aes256_ctx_size
	, c_cmac_aes256_set_key
	, c_cmac_aes256_update
	, c_cmac_aes256_digest

	, c_cmac_des3_ctx_size
	, c_cmac_des3_set_key
	, c_cmac_des3_update
	, c_cmac_des3_digest

	, c_poly1305_aes_ctx_size
	, c_poly1305_aes_digest_size
	, c_poly1305_aes_set_key
	, c_poly1305_aes_set_nonce
	, c_poly1305_aes_update
	, c_poly1305_aes_digest
	) where

import Nettle.Utils

-- internal functions are not camelCase on purpose
{-# ANN module "HLint: ignore Use camelCase" #-}

#include "nettle-hash.h"

type NettleHashInit = Ptr Word8 -> IO ()
type NettleHashUpdate = Ptr Word8 -> Word -> Ptr Word8 -> IO ()
#if (NETTLE_VERSION_MAJOR > 3)
type NettleHashDigest = Ptr Word8 -> Ptr Word8 -> IO ()
#else
type NettleHashDigest = Ptr Word8 -> Word -> Ptr Word8 -> IO ()
#endif

-- | Call a nettle @*_digest@ function, adapting to the Nettle API.
--   Nettle 4 dropped the @digest_size@ argument; the @digestSize@ argument
--   is only used on Nettle 3.x.
callNettleHashDigest :: NettleHashDigest -> Int -> Ptr Word8 -> Ptr Word8 -> IO ()
#if (NETTLE_VERSION_MAJOR > 3)
callNettleHashDigest digestfun _digestSize ctxptr digestptr = digestfun ctxptr digestptr
#else
callNettleHashDigest digestfun digestSize ctxptr digestptr = digestfun ctxptr (fromIntegral digestSize) digestptr
#endif


c_sha256_ctx_size :: Int
c_sha256_ctx_size = #{size struct sha256_ctx}
c_sha256_digest_size :: Int
c_sha256_digest_size = #{const SHA256_DIGEST_SIZE}
c_sha256_block_size :: Int
c_sha256_block_size = #{const SHA256_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha256_init"
	c_sha256_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha256_update"
	c_sha256_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha256_digest"
	c_sha256_digest :: NettleHashDigest

c_sha224_ctx_size :: Int
c_sha224_ctx_size = #{size struct sha224_ctx}
c_sha224_digest_size :: Int
c_sha224_digest_size = #{const SHA224_DIGEST_SIZE}
c_sha224_block_size :: Int
c_sha224_block_size = #{const SHA224_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha224_init"
	c_sha224_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha256_update"
	c_sha224_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha224_digest"
	c_sha224_digest :: NettleHashDigest

c_sha512_ctx_size :: Int
c_sha512_ctx_size = #{size struct sha512_ctx}
c_sha512_digest_size :: Int
c_sha512_digest_size = #{const SHA512_DIGEST_SIZE}
c_sha512_block_size :: Int
c_sha512_block_size = #{const SHA512_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha512_init"
	c_sha512_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha512_update"
	c_sha512_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha512_digest"
	c_sha512_digest :: NettleHashDigest

c_sha384_ctx_size :: Int
c_sha384_ctx_size = #{size struct sha384_ctx}
c_sha384_digest_size :: Int
c_sha384_digest_size = #{const SHA384_DIGEST_SIZE}
c_sha384_block_size :: Int
c_sha384_block_size = #{const SHA384_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha384_init"
	c_sha384_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha512_update"
	c_sha384_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha384_digest"
	c_sha384_digest :: NettleHashDigest

c_sha3_224_ctx_size :: Int
c_sha3_224_ctx_size = #{size struct sha3_224_ctx}
c_sha3_224_digest_size :: Int
c_sha3_224_digest_size = #{const SHA3_224_DIGEST_SIZE}
c_sha3_224_block_size :: Int
c_sha3_224_block_size = #{const SHA3_224_BLOCK_SIZE}
#if (NETTLE_VERSION_MAJOR > 3)
foreign import ccall unsafe "nettle_sha3_init"
	c_sha3_init :: NettleHashInit

-- Nettle 4 uses one context struct and init function for all SHA3 variants
c_sha3_224_init :: NettleHashInit
c_sha3_224_init = c_sha3_init
c_sha3_256_init :: NettleHashInit
c_sha3_256_init = c_sha3_init
c_sha3_384_init :: NettleHashInit
c_sha3_384_init = c_sha3_init
c_sha3_512_init :: NettleHashInit
c_sha3_512_init = c_sha3_init
#else
foreign import ccall unsafe "nettle_sha3_224_init"
	c_sha3_224_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha3_256_init"
	c_sha3_256_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha3_384_init"
	c_sha3_384_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha3_512_init"
	c_sha3_512_init :: NettleHashInit
#endif
foreign import ccall unsafe "nettle_sha3_224_update"
	c_sha3_224_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha3_224_digest"
	c_sha3_224_digest :: NettleHashDigest

c_sha3_256_ctx_size :: Int
c_sha3_256_ctx_size = #{size struct sha3_256_ctx}
c_sha3_256_digest_size :: Int
c_sha3_256_digest_size = #{const SHA3_256_DIGEST_SIZE}
c_sha3_256_block_size :: Int
c_sha3_256_block_size = #{const SHA3_256_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha3_256_update"
	c_sha3_256_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha3_256_digest"
	c_sha3_256_digest :: NettleHashDigest

c_sha3_384_ctx_size :: Int
c_sha3_384_ctx_size = #{size struct sha3_384_ctx}
c_sha3_384_digest_size :: Int
c_sha3_384_digest_size = #{const SHA3_384_DIGEST_SIZE}
c_sha3_384_block_size :: Int
c_sha3_384_block_size = #{const SHA3_384_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha3_384_update"
	c_sha3_384_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha3_384_digest"
	c_sha3_384_digest :: NettleHashDigest

c_sha3_512_ctx_size :: Int
c_sha3_512_ctx_size = #{size struct sha3_512_ctx}
c_sha3_512_digest_size :: Int
c_sha3_512_digest_size = #{const SHA3_512_DIGEST_SIZE}
c_sha3_512_block_size :: Int
c_sha3_512_block_size = #{const SHA3_512_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha3_512_update"
	c_sha3_512_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha3_512_digest"
	c_sha3_512_digest :: NettleHashDigest

c_sm3_ctx_size :: Int
c_sm3_ctx_size = #{size struct sm3_ctx}
c_sm3_digest_size :: Int
c_sm3_digest_size = #{const SM3_DIGEST_SIZE}
c_sm3_block_size :: Int
c_sm3_block_size = #{const SM3_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sm3_init"
	c_sm3_init :: NettleHashInit
foreign import ccall unsafe "nettle_sm3_update"
	c_sm3_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sm3_digest"
	c_sm3_digest :: NettleHashDigest

c_streebog512_ctx_size :: Int
c_streebog512_ctx_size = #{size struct streebog512_ctx}
c_streebog512_digest_size :: Int
c_streebog512_digest_size = #{const STREEBOG512_DIGEST_SIZE}
c_streebog512_block_size :: Int
c_streebog512_block_size = #{const STREEBOG512_BLOCK_SIZE}
foreign import ccall unsafe "nettle_streebog512_init"
	c_streebog512_init :: NettleHashInit
foreign import ccall unsafe "nettle_streebog512_update"
	c_streebog512_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_streebog512_digest"
	c_streebog512_digest :: NettleHashDigest

c_streebog256_ctx_size :: Int
c_streebog256_ctx_size = #{size struct streebog256_ctx}
c_streebog256_digest_size :: Int
c_streebog256_digest_size = #{const STREEBOG256_DIGEST_SIZE}
c_streebog256_block_size :: Int
c_streebog256_block_size = #{const STREEBOG256_BLOCK_SIZE}
foreign import ccall unsafe "nettle_streebog256_init"
	c_streebog256_init :: NettleHashInit
foreign import ccall unsafe "nettle_streebog512_update"
	c_streebog256_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_streebog256_digest"
	c_streebog256_digest :: NettleHashDigest

-- SHAKE128 was added in Nettle 3.10 and is not available in 3.9.x.
-- SHAKE256 reuses the SHA3-256 context and update function from above.
#if (NETTLE_VERSION_MAJOR > 3 || (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 10))
c_sha3_128_ctx_size :: Int
c_sha3_128_ctx_size = #{size struct sha3_128_ctx}
#if (NETTLE_VERSION_MAJOR > 3)
foreign import ccall unsafe "nettle_sha3_init"
	c_sha3_128_init :: NettleHashInit
#else
foreign import ccall unsafe "nettle_sha3_128_init"
	c_sha3_128_init :: NettleHashInit
#endif
foreign import ccall unsafe "nettle_sha3_128_update"
	c_sha3_128_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha3_128_shake"
	c_sha3_128_shake :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
#endif
foreign import ccall unsafe "nettle_sha3_256_shake"
	c_sha3_256_shake :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()

c_md5_ctx_size :: Int
c_md5_ctx_size = #{size struct md5_ctx}
c_md5_digest_size :: Int
c_md5_digest_size = #{const MD5_DIGEST_SIZE}
c_md5_block_size :: Int
c_md5_block_size = #{const MD5_BLOCK_SIZE}
foreign import ccall unsafe "nettle_md5_init"
	c_md5_init :: NettleHashInit
foreign import ccall unsafe "nettle_md5_update"
	c_md5_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_md5_digest"
	c_md5_digest :: NettleHashDigest

c_md2_ctx_size :: Int
c_md2_ctx_size = #{size struct md2_ctx}
c_md2_digest_size :: Int
c_md2_digest_size = #{const MD2_DIGEST_SIZE}
c_md2_block_size :: Int
c_md2_block_size = #{const MD2_BLOCK_SIZE}
foreign import ccall unsafe "nettle_md2_init"
	c_md2_init :: NettleHashInit
foreign import ccall unsafe "nettle_md2_update"
	c_md2_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_md2_digest"
	c_md2_digest :: NettleHashDigest

c_md4_ctx_size :: Int
c_md4_ctx_size = #{size struct md4_ctx}
c_md4_digest_size :: Int
c_md4_digest_size = #{const MD4_DIGEST_SIZE}
c_md4_block_size :: Int
c_md4_block_size = #{const MD4_BLOCK_SIZE}
foreign import ccall unsafe "nettle_md4_init"
	c_md4_init :: NettleHashInit
foreign import ccall unsafe "nettle_md4_update"
	c_md4_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_md4_digest"
	c_md4_digest :: NettleHashDigest

c_ripemd160_ctx_size :: Int
c_ripemd160_ctx_size = #{size struct ripemd160_ctx}
c_ripemd160_digest_size :: Int
c_ripemd160_digest_size = #{const RIPEMD160_DIGEST_SIZE}
c_ripemd160_block_size :: Int
c_ripemd160_block_size = #{const RIPEMD160_BLOCK_SIZE}
foreign import ccall unsafe "nettle_ripemd160_init"
	c_ripemd160_init :: NettleHashInit
foreign import ccall unsafe "nettle_ripemd160_update"
	c_ripemd160_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_ripemd160_digest"
	c_ripemd160_digest :: NettleHashDigest

c_sha1_ctx_size :: Int
c_sha1_ctx_size = #{size struct sha1_ctx}
c_sha1_digest_size :: Int
c_sha1_digest_size = #{const SHA1_DIGEST_SIZE}
c_sha1_block_size :: Int
c_sha1_block_size = #{const SHA1_BLOCK_SIZE}
foreign import ccall unsafe "nettle_sha1_init"
	c_sha1_init :: NettleHashInit
foreign import ccall unsafe "nettle_sha1_update"
	c_sha1_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_sha1_digest"
	c_sha1_digest :: NettleHashDigest

c_gosthash94_ctx_size :: Int
c_gosthash94_ctx_size = #{size struct gosthash94_ctx}
c_gosthash94_digest_size :: Int
c_gosthash94_digest_size = #{const GOSTHASH94_DIGEST_SIZE}
c_gosthash94_block_size :: Int
c_gosthash94_block_size = #{const GOSTHASH94_BLOCK_SIZE}
foreign import ccall unsafe "nettle_gosthash94_init"
	c_gosthash94_init :: NettleHashInit
foreign import ccall unsafe "nettle_gosthash94_update"
	c_gosthash94_update :: NettleHashUpdate
foreign import ccall unsafe "nettle_gosthash94_digest"
	c_gosthash94_digest :: NettleHashDigest


c_umac32_ctx_size :: Int
c_umac32_ctx_size = #{size struct umac32_ctx}
c_umac32_digest_size :: Int
c_umac32_digest_size = #{const UMAC32_DIGEST_SIZE}
foreign import ccall unsafe "nettle_umac32_set_key"
	c_umac32_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac32_set_nonce"
	c_umac32_set_nonce :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac32_update"
	c_umac32_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac32_digest"
	c_umac32_digest :: NettleHashDigest

c_umac64_ctx_size :: Int
c_umac64_ctx_size = #{size struct umac64_ctx}
c_umac64_digest_size :: Int
c_umac64_digest_size = #{const UMAC64_DIGEST_SIZE}
foreign import ccall unsafe "nettle_umac64_set_key"
	c_umac64_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac64_set_nonce"
	c_umac64_set_nonce :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac64_update"
	c_umac64_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac64_digest"
	c_umac64_digest :: NettleHashDigest

c_umac96_ctx_size :: Int
c_umac96_ctx_size = #{size struct umac96_ctx}
c_umac96_digest_size :: Int
c_umac96_digest_size = #{const UMAC96_DIGEST_SIZE}
foreign import ccall unsafe "nettle_umac96_set_key"
	c_umac96_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac96_set_nonce"
	c_umac96_set_nonce :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac96_update"
	c_umac96_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac96_digest"
	c_umac96_digest :: NettleHashDigest

c_umac128_ctx_size :: Int
c_umac128_ctx_size = #{size struct umac128_ctx}
c_umac128_digest_size :: Int
c_umac128_digest_size = #{const UMAC128_DIGEST_SIZE}
foreign import ccall unsafe "nettle_umac128_set_key"
	c_umac128_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac128_set_nonce"
	c_umac128_set_nonce :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac128_update"
	c_umac128_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_umac128_digest"
	c_umac128_digest :: NettleHashDigest

c_cmac_aes128_ctx_size :: Int
c_cmac_aes128_ctx_size = #{size struct cmac_aes128_ctx}
foreign import ccall unsafe "nettle_cmac_aes128_set_key"
	c_cmac_aes128_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_aes128_update"
	c_cmac_aes128_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_aes128_digest"
	c_cmac_aes128_digest :: NettleHashDigest

c_cmac_aes256_ctx_size :: Int
c_cmac_aes256_ctx_size = #{size struct cmac_aes256_ctx}
foreign import ccall unsafe "nettle_cmac_aes256_set_key"
	c_cmac_aes256_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_aes256_update"
	c_cmac_aes256_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_aes256_digest"
	c_cmac_aes256_digest :: NettleHashDigest

c_cmac_des3_ctx_size :: Int
c_cmac_des3_ctx_size = #{size struct cmac_des3_ctx}
foreign import ccall unsafe "nettle_cmac_des3_set_key"
	c_cmac_des3_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_des3_update"
	c_cmac_des3_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_cmac_des3_digest"
	c_cmac_des3_digest :: NettleHashDigest

c_poly1305_aes_ctx_size :: Int
c_poly1305_aes_ctx_size = #{size struct poly1305_aes_ctx}
c_poly1305_aes_digest_size :: Int
c_poly1305_aes_digest_size = #{const POLY1305_AES_DIGEST_SIZE}
foreign import ccall unsafe "nettle_poly1305_aes_set_key"
	c_poly1305_aes_set_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_poly1305_aes_set_nonce"
	c_poly1305_aes_set_nonce :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_poly1305_aes_update"
	c_poly1305_aes_update :: Ptr Word8 -> Word -> Ptr Word8 -> IO ()
foreign import ccall unsafe "nettle_poly1305_aes_digest"
	c_poly1305_aes_digest :: NettleHashDigest
