
#ifndef _HS_NETTLE_HASH_H
#define _HS_NETTLE_HASH_H _HS_NETTLE_HASH_H

#include <nettle/version.h>

#if (NETTLE_VERSION_MAJOR != 3)
#error unsupported nettle version
#endif

#include <sys/types.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>
#include <nettle/memxor.h>

/* hash algorithms */
#include <nettle/gosthash94.h>
#include <nettle/md2.h>
#include <nettle/md4.h>
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>

#include <nettle/umac.h>

void hs_nettle_sha3_224_digest(struct sha3_224_ctx *ctx, size_t length, uint8_t *digest);
void hs_nettle_sha3_256_digest(struct sha3_256_ctx *ctx, size_t length, uint8_t *digest);
void hs_nettle_sha3_384_digest(struct sha3_384_ctx *ctx, size_t length, uint8_t *digest);
void hs_nettle_sha3_512_digest(struct sha3_512_ctx *ctx, size_t length, uint8_t *digest);

#endif
