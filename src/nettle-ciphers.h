
#ifndef _HS_NETTLE_CIPHERS_H
#define _HS_NETTLE_CIPHERS_H _HS_NETTLE_CIPHERS_H

#include <sys/types.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>
#include <nettle/memxor.h>

/* block ciphers */
#include <nettle/aes.h>
#include <nettle/arctwo.h>
#include <nettle/blowfish.h>
#include <nettle/camellia.h>
#include <nettle/cast128.h>
#include <nettle/des.h>
#include <nettle/serpent.h>
#include <nettle/twofish.h>

/* stream ciphers */
#include <nettle/arcfour.h>
#include <nettle/salsa20.h>

void hs_nettle_cfb_encrypt(void *ctx, nettle_crypt_func *f,
	unsigned block_size, uint8_t *iv,
	unsigned length, uint8_t *dst,
	const uint8_t *src);

/* takes *ENCRYPTION* function f */
void hs_nettle_cfb_decrypt(void *ctx, nettle_crypt_func *f,
	unsigned block_size, uint8_t *iv,
	unsigned length, uint8_t *dst,
	const uint8_t *src);


struct hs_aes_ctx {
	struct aes_ctx encrypt, decrypt;
};
void hs_nettle_aes_init(struct hs_aes_ctx *ctx, unsigned int key_size, const char *key);


struct hs_camellia_ctx {
	struct camellia_ctx encrypt, decrypt;
};
void hs_nettle_camellia_init(struct hs_camellia_ctx *ctx, unsigned int key_size, const char *key);

#endif
