
#include "nettle.h"

#undef NDEBUG
#include <assert.h>

void hs_nettle_cfb_encrypt(void *ctx, nettle_crypt_func *f,
	unsigned block_size, uint8_t *iv,
	unsigned length, uint8_t *dst,
	const uint8_t *src) {
	unsigned i;

	if (0 == length) return;
	assert(0 != block_size && length % block_size == 0);

	f(ctx, block_size, dst, iv);
	memxor(dst, src, block_size);
	for (i = block_size; i < length; i += block_size) {
		f(ctx, block_size, dst + i, dst + i - block_size);
		memxor(dst +i , src + i, block_size);
	}
}

void hs_nettle_cfb_decrypt(void *ctx, nettle_crypt_func *f,
	unsigned block_size, uint8_t *iv,
	unsigned length, uint8_t *dst,
	const uint8_t *src) {
	unsigned i;

	if (0 == length) return;
	assert(0 != block_size && length % block_size == 0);

	f(ctx, block_size, dst, iv);
	memxor(dst, src, block_size);
	for (i = block_size; i < length; i += block_size) {
		f(ctx, block_size, dst + i, src + i - block_size);
		memxor(dst +i , src + i, block_size);
	}
}

void hs_nettle_aes_init(struct hs_aes_ctx *ctx, unsigned int key_size, const char *key) {
	assert(16 == key_size || 24 == key_size || 32 == key_size);

	aes_set_encrypt_key(&ctx->encrypt, key_size, key);
	aes_invert_key(&ctx->decrypt, &ctx->encrypt);
}

void hs_nettle_camellia_init(struct hs_camellia_ctx *ctx, unsigned int key_size, const char *key) {
	assert(16 == key_size || 24 == key_size || 32 == key_size);

	camellia_set_encrypt_key(&ctx->encrypt, key_size, key);
	camellia_invert_key(&ctx->decrypt, &ctx->encrypt);
}
