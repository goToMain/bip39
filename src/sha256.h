#ifndef SHA256_BLOCK_SHA256_H
#define SHA256_BLOCK_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define blk_SHA256_BLKSIZE 64
#define SHA256_LEN 32

struct blk_SHA256_CTX {
	uint32_t state[8];
	uint64_t size;
	uint32_t offset;
	uint8_t buf[blk_SHA256_BLKSIZE];
};

typedef struct blk_SHA256_CTX blk_SHA256_CTX;

void blk_SHA256_Init(blk_SHA256_CTX *ctx);
void blk_SHA256_Update(blk_SHA256_CTX *ctx, const void *data, size_t len);
void blk_SHA256_Final(unsigned char *digest, blk_SHA256_CTX *ctx);

void compute_sha256(const uint8_t *buf, size_t size, uint8_t digest[SHA256_LEN]);
bool verify_sha256(const uint8_t *buf, size_t size, uint8_t digest_in[SHA256_LEN]);

#define sha256_ctx blk_SHA256_CTX
#define sha256_init blk_SHA256_Init
#define sha256_update blk_SHA256_Update
#define sha256_final blk_SHA256_Final

#endif
