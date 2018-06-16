
#include "nettle-hash.h"

#undef NDEBUG
#include <assert.h>

#if (NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR < 2)

void hs_nettle_sha3_224_digest(struct sha3_224_ctx *ctx, size_t length, uint8_t *digest) {
	nettle_sha3_224_digest(ctx, length, digest);
}

void hs_nettle_sha3_256_digest(struct sha3_256_ctx *ctx, size_t length, uint8_t *digest) {
	nettle_sha3_256_digest(ctx, length, digest);
}

void hs_nettle_sha3_384_digest(struct sha3_384_ctx *ctx, size_t length, uint8_t *digest) {
	nettle_sha3_384_digest(ctx, length, digest);
}

void hs_nettle_sha3_512_digest(struct sha3_512_ctx *ctx, size_t length, uint8_t *digest) {
	nettle_sha3_512_digest(ctx, length, digest);
}

#else

/* copy some internal functions from nettle */
#include <stddef.h>
#include <string.h>

#include <nettle/memxor.h>
#include <nettle/macros.h>

static void sha3_absorb(struct sha3_state *state, unsigned length, const uint8_t *data) {
	assert((length & 7) == 0);
#if WORDS_BIGENDIAN
	{
		uint64_t *p;
		for (p = state->a; length > 0; p++, length -= 8, data += 8)
			*p ^= LE_READ_UINT64(data);
	}
#else /* !WORDS_BIGENDIAN */
	nettle_memxor(state->a, data, length);
#endif

	nettle_sha3_permute(state);
}

static void _pre_finalized_sha3_pad(struct sha3_state *state, unsigned block_size, uint8_t *block, unsigned pos) {
	assert(pos < block_size);
	block[pos++] = 1; /* in nettle 3.2 this became `6` */

	memset(block + pos, 0, block_size - pos);
	block[block_size - 1] |= 0x80;

	sha3_absorb(state, block_size, block);
}

static void _nettle_write_le64(size_t length, uint8_t *dst, uint64_t *src) {
	size_t i;
	size_t words;
	unsigned leftover;

	words = length / 8;
	leftover = length % 8;

	for (i = 0; i < words; i++, dst += 8)
		LE_WRITE_UINT64(dst, src[i]);

	if (leftover) {
		uint64_t word;

		word = src[i];

		do
		{
			*dst++ = word & 0xff;
			word >>= 8;
		} while (--leftover);
	}
}


void hs_nettle_sha3_224_digest(struct sha3_224_ctx *ctx, size_t length, uint8_t *digest) {
	_pre_finalized_sha3_pad(&ctx->state, SHA3_224_BLOCK_SIZE, ctx->block, ctx->index);
	_nettle_write_le64(length, digest, ctx->state.a);
	sha3_224_init(ctx);
}

void hs_nettle_sha3_256_digest(struct sha3_256_ctx *ctx, size_t length, uint8_t *digest) {
	_pre_finalized_sha3_pad(&ctx->state, SHA3_256_BLOCK_SIZE, ctx->block, ctx->index);
	_nettle_write_le64(length, digest, ctx->state.a);
	sha3_256_init(ctx);
}

void hs_nettle_sha3_384_digest(struct sha3_384_ctx *ctx, size_t length, uint8_t *digest) {
	_pre_finalized_sha3_pad(&ctx->state, SHA3_384_BLOCK_SIZE, ctx->block, ctx->index);
	_nettle_write_le64(length, digest, ctx->state.a);
	sha3_384_init(ctx);
}

void hs_nettle_sha3_512_digest(struct sha3_512_ctx *ctx, size_t length, uint8_t *digest) {
	_pre_finalized_sha3_pad(&ctx->state, SHA3_512_BLOCK_SIZE, ctx->block, ctx->index);
	_nettle_write_le64(length, digest, ctx->state.a);
	sha3_512_init(ctx);
}

#endif
