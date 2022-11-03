/**********************************************************************
  Copyright(c) 2022 Linaro Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Linaro Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdint.h>
#include <string.h>
#include "xxhash_mb.h"

/*-****************************
 * Simple Hash Functions
 *****************************/

/**
 * xxh32() - calculate the 32-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 32-bit hash of the data.
 */
uint32_t
xxh32(const void *input, size_t length, uint32_t seed);

/**
 * xxh64() - calculate the 64-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 64-bit hash of the data.
 */
uint64_t
xxh64(const void *input, size_t length, uint64_t seed);

/*-****************************
 * Streaming Hash Functions
 *****************************/

/**
 * xxh32_reset() - reset the xxh32 state to start a new hashing operation
 *
 * @state: The xxh32 state to reset.
 * @seed:  Initialize the hash state with this seed.
 *
 * Call this function on any xxh32_state to prepare for a new hashing operation.
 */
void
xxh32_reset(XXH32_HASH_CTX *ctx, uint32_t seed);

/**
 * xxh32_update() - hash the data given and update the xxh32 state
 *
 * @state:  The xxh32 state to update.
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 *
 * After calling xxh32_reset() call xxh32_update() as many times as necessary.
 *
 * Return:  Zero on success, otherwise an error code.
 */
int
xxh32_update(XXH32_HASH_CTX *ctx, const void *input, size_t length);

/**
 * xxh32_digest() - produce the current xxh32 hash
 *
 * @state: Produce the current xxh32 hash of this state.
 *
 * A hash value can be produced at any time. It is still possible to continue
 * inserting input into the hash state after a call to xxh32_digest(), and
 * generate new hashes later on, by calling xxh32_digest() again.
 *
 * Return: The xxh32 hash stored in the state.
 */
void
xxh32_digest(XXH32_HASH_CTX *ctx);

/**
 * xxh64_reset() - reset the xxh64 state to start a new hashing operation
 *
 * @state: The xxh64 state to reset.
 * @seed:  Initialize the hash state with this seed.
 */
void
xxh64_reset(XXH64_HASH_CTX *ctx, uint64_t seed);

/**
 * xxh64_update() - hash the data given and update the xxh64 state
 * @state:  The xxh64 state to update.
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 *
 * After calling xxh64_reset() call xxh64_update() as many times as necessary.
 *
 * Return:  Zero on success, otherwise an error code.
 */
int
xxh64_update(XXH64_HASH_CTX *ctx, const void *input, size_t length);

/**
 * xxh64_digest() - produce the current xxh64 hash
 *
 * @state: Produce the current xxh64 hash of this state.
 *
 * A hash value can be produced at any time. It is still possible to continue
 * inserting input into the hash state after a call to xxh64_digest(), and
 * generate new hashes later on, by calling xxh64_digest() again.
 *
 * Return: The xxh64 hash stored in the state.
 */
void
xxh64_digest(XXH64_HASH_CTX *ctx);

/*-**************************
 * Utils
 ***************************/

/*-*************************************
 * Macros
 **************************************/
#define XXH_rotl32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_rotl64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

/*-*************************************
 * Constants
 **************************************/
static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 = 668265263U;
static const uint32_t PRIME32_5 = 374761393U;

static const uint64_t PRIME64_1 = 11400714785074694791ULL;
static const uint64_t PRIME64_2 = 14029467366897019727ULL;
static const uint64_t PRIME64_3 = 1609587929392839161ULL;
static const uint64_t PRIME64_4 = 9650029242287828579ULL;
static const uint64_t PRIME64_5 = 2870177450012600261ULL;

void
xxh32_ctx_mgr_init_base(XXH32_HASH_CTX_MGR *mgr)
{
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_submit_base(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx, const void *buffer,
                          uint32_t len, HASH_CTX_FLAG flags)
{
        if (flags & (~HASH_ENTIRE)) {
                // User should not pass anything other than FIRST, UPDATE or
                // LAST.
                ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_PROCESSING) && (flags == HASH_ENTIRE)) {
                // Cannot submit a new entire job to a currently processing
                // job.
                ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_COMPLETE) && !(flags & HASH_FIRST)) {
                // Cannot update a finished job.
                ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
                return ctx;
        }

        switch (flags) {
        case HASH_FIRST:
                xxh32_reset(ctx, ctx->seed);
                xxh32_update(ctx, buffer, len);
                break;
        case HASH_UPDATE:
                xxh32_update(ctx, buffer, len);
                break;
        case HASH_LAST:
                xxh32_update(ctx, buffer, len);
                xxh32_digest(ctx);
                break;
        case HASH_ENTIRE:
                xxh32_reset(ctx, ctx->seed);
                xxh32_update(ctx, buffer, len);
                xxh32_digest(ctx);
                break;
        }

        return ctx;
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_flush_base(XXH32_HASH_CTX_MGR *mgr)
{
        return NULL;
}

void
xxh32_reset(XXH32_HASH_CTX *ctx, uint32_t seed)
{
        // Init digest
        ctx->job.digest[0] = seed + PRIME32_1 + PRIME32_2;
        ctx->job.digest[1] = seed + PRIME32_2;
        ctx->job.digest[2] = seed + 0;
        ctx->job.digest[3] = seed - PRIME32_1;

        // Reset byte counter
        ctx->total_length = 0;

        // Clear extra blocks
        ctx->partial_block_buffer_length = 0;

        // If we made it here, there were no errors during this call to submit
        ctx->error = HASH_CTX_ERROR_NONE;

        // Mark it as processing
        ctx->status = HASH_CTX_STS_PROCESSING;
}

static uint32_t
xxh32_round(uint32_t seed, const uint32_t input)
{
        seed += input * PRIME32_2;
        seed = XXH_rotl32(seed, 13);
        seed *= PRIME32_1;
        return seed;
}

/* assume partial_block_buffer_length < 16!!! Need to fix? */
int
xxh32_update(XXH32_HASH_CTX *ctx, const void *input, size_t len)
{
        const uint8_t *p = (const uint8_t *) input;
        const uint8_t *const b_end = p + len;

        ctx->total_length += len;
        ctx->large_len |= (len >= 16) | (ctx->total_length >= 16);

        if (ctx->partial_block_buffer_length + len < 16) {
                /* fill in the partial block buffer */
                memcpy(ctx->partial_block_buffer + ctx->partial_block_buffer_length, input, len);
                ctx->partial_block_buffer_length += (uint32_t) len;
                return 0;
        }

        if (ctx->partial_block_buffer_length) {
                /* data left from previous update */
                memcpy(ctx->partial_block_buffer + ctx->partial_block_buffer_length, input,
                       16 - ctx->partial_block_buffer_length);
                {
                        const uint32_t *p32 = (const uint32_t *) ctx->partial_block_buffer;
                        ctx->job.digest[0] = xxh32_round(ctx->job.digest[0], *p32);
                        p32++;
                        ctx->job.digest[1] = xxh32_round(ctx->job.digest[1], *p32);
                        p32++;
                        ctx->job.digest[2] = xxh32_round(ctx->job.digest[2], *p32);
                        p32++;
                        ctx->job.digest[3] = xxh32_round(ctx->job.digest[3], *p32);
                }
                p += 16 - ctx->partial_block_buffer_length;
                ctx->partial_block_buffer_length = 0;
        }

        if (p <= b_end - 16) {
                const uint8_t *const limit = b_end - 16;

                do {
                        ctx->job.digest[0] = xxh32_round(ctx->job.digest[0], *(uint32_t *) p);
                        p += 4;
                        ctx->job.digest[1] = xxh32_round(ctx->job.digest[1], *(uint32_t *) p);
                        p += 4;
                        ctx->job.digest[2] = xxh32_round(ctx->job.digest[2], *(uint32_t *) p);
                        p += 4;
                        ctx->job.digest[3] = xxh32_round(ctx->job.digest[3], *(uint32_t *) p);
                        p += 4;
                } while (p <= limit);
        }

        if (p < b_end) {
                memcpy(ctx->partial_block_buffer, p, (size_t) (b_end - p));
                ctx->partial_block_buffer_length = (uint32_t) (b_end - p);
        }

        return 0;
}

void
xxh32_digest(XXH32_HASH_CTX *ctx)
{
        const uint8_t *p = (const uint8_t *) ctx->partial_block_buffer;
        const uint8_t *const b_end =
                (const uint8_t *) ctx->partial_block_buffer + ctx->partial_block_buffer_length;

        if (ctx->large_len) {
                ctx->job.result_digest =
                        XXH_rotl32(ctx->job.digest[0], 1) + XXH_rotl32(ctx->job.digest[1], 7) +
                        XXH_rotl32(ctx->job.digest[2], 12) + XXH_rotl32(ctx->job.digest[3], 18);
        } else {
                /* seed + PRIME32_5 */
                ctx->job.result_digest = ctx->job.digest[2] + PRIME32_5;
        }

        ctx->job.result_digest += ctx->total_length;

        while (p + 4 <= b_end) {
                ctx->job.result_digest += *(uint32_t *) p * PRIME32_3;
                ctx->job.result_digest = XXH_rotl32(ctx->job.result_digest, 17) * PRIME32_4;
                p += 4;
        }

        while (p < b_end) {
                ctx->job.result_digest += *p * PRIME32_5;
                ctx->job.result_digest = XXH_rotl32(ctx->job.result_digest, 11) * PRIME32_1;
                p++;
        }

        ctx->job.result_digest ^= ctx->job.result_digest >> 15;
        ctx->job.result_digest *= PRIME32_2;
        ctx->job.result_digest ^= ctx->job.result_digest >> 13;
        ctx->job.result_digest *= PRIME32_3;
        ctx->job.result_digest ^= ctx->job.result_digest >> 16;
}

void
xxh64_ctx_mgr_init_base(XXH64_HASH_CTX_MGR *mgr)
{
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_submit_base(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx, const void *buffer,
                          uint64_t len, HASH_CTX_FLAG flags)
{
        if (flags & (~HASH_ENTIRE)) {
                ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_PROCESSING) && (flags == HASH_ENTIRE)) {
                ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_COMPLETE) && !(flags & HASH_FIRST)) {
                // Cannot update a finished job.
                ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
                return ctx;
        }

        switch (flags) {
        case HASH_FIRST:
                xxh64_reset(ctx, ctx->seed);
                xxh64_update(ctx, buffer, len);
                break;
        case HASH_UPDATE:
                xxh64_update(ctx, buffer, len);
                break;
        case HASH_LAST:
                xxh64_update(ctx, buffer, len);
                xxh64_digest(ctx);
                break;
        case HASH_ENTIRE:
                xxh64_reset(ctx, ctx->seed);
                xxh64_update(ctx, buffer, len);
                xxh64_digest(ctx);
                break;
        }
        return ctx;
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_flush_base(XXH64_HASH_CTX_MGR *mgr)
{
        return NULL;
}

void
xxh64_reset(XXH64_HASH_CTX *ctx, uint64_t seed)
{
        // Init digest
        ctx->job.digest[0] = seed + PRIME64_1 + PRIME64_2;
        ctx->job.digest[1] = seed + PRIME64_2;
        ctx->job.digest[2] = seed + 0;
        ctx->job.digest[3] = seed - PRIME64_1;

        // Reset byte counter
        ctx->total_length = 0;

        // Clear extra blocks
        ctx->partial_block_buffer_length = 0;

        // If we made it here, there were no errors during this call to submit
        ctx->error = HASH_CTX_ERROR_NONE;

        // Mark it as processing
        ctx->status = HASH_CTX_STS_PROCESSING;
}

static uint64_t
xxh64_round(uint64_t acc, const uint64_t input)
{
        acc += input * PRIME64_2;
        acc = XXH_rotl64(acc, 31);
        acc *= PRIME64_1;
        return acc;
}

static uint64_t
xxh64_merge_round(uint64_t acc, uint64_t val)
{
        val = xxh64_round(0, val);
        acc ^= val;
        acc = acc * PRIME64_1 + PRIME64_4;
        return acc;
}

int
xxh64_update(XXH64_HASH_CTX *ctx, const void *input, size_t len)
{
        const uint8_t *p = (const uint8_t *) input;
        const uint8_t *const b_end = p + len;

        ctx->total_length += len;

        if (ctx->partial_block_buffer_length + len < 32) {
                // fill in the partial block buffer
                memcpy(ctx->partial_block_buffer + ctx->partial_block_buffer_length, input, len);
                ctx->partial_block_buffer_length += (uint32_t) len;
                return 0;
        }

        if (ctx->partial_block_buffer_length) {
                // data left from previous update
                memcpy(ctx->partial_block_buffer + ctx->partial_block_buffer_length, input,
                       32 - ctx->partial_block_buffer_length);
                {
                        const uint64_t *p64 = (const uint64_t *) ctx->partial_block_buffer;
                        ctx->job.digest[0] = xxh64_round(ctx->job.digest[0], *p64);
                        p64++;
                        ctx->job.digest[1] = xxh64_round(ctx->job.digest[1], *p64);
                        p64++;
                        ctx->job.digest[2] = xxh64_round(ctx->job.digest[2], *p64);
                        p64++;
                        ctx->job.digest[3] = xxh64_round(ctx->job.digest[3], *p64);
                }
                p += 32 - ctx->partial_block_buffer_length;
                ctx->partial_block_buffer_length = 0;
        }

        if (p <= b_end - 32) {
                const uint8_t *const limit = b_end - 32;
                uint64_t v1 = ctx->job.digest[0];
                uint64_t v2 = ctx->job.digest[1];
                uint64_t v3 = ctx->job.digest[2];
                uint64_t v4 = ctx->job.digest[3];

                do {
                        v1 = xxh64_round(v1, *(uint64_t *) p);
                        p += 8;
                        v2 = xxh64_round(v2, *(uint64_t *) p);
                        p += 8;
                        v3 = xxh64_round(v3, *(uint64_t *) p);
                        p += 8;
                        v4 = xxh64_round(v4, *(uint64_t *) p);
                        p += 8;
                } while (p <= limit);

                ctx->job.digest[0] = v1;
                ctx->job.digest[1] = v2;
                ctx->job.digest[2] = v3;
                ctx->job.digest[3] = v4;
        }

        if (p < b_end) {
                memcpy(ctx->partial_block_buffer, p, (size_t) (b_end - p));
                ctx->partial_block_buffer_length = (uint32_t) (b_end - p);
        }

        return 0;
}

void
xxh64_digest(XXH64_HASH_CTX *ctx)
{
        const uint8_t *p = (const uint8_t *) ctx->partial_block_buffer;
        const uint8_t *const b_end =
                (const uint8_t *) ctx->partial_block_buffer + ctx->partial_block_buffer_length;
        uint64_t h64;

        if (ctx->total_length >= 32) {
                const uint8_t *const limit = b_end - 32;
                uint64_t v1 = ctx->job.digest[0];
                uint64_t v2 = ctx->job.digest[1];
                uint64_t v3 = ctx->job.digest[2];
                uint64_t v4 = ctx->job.digest[3];

                while (p <= limit) {
                        v1 = xxh64_round(v1, *(uint64_t *) p);
                        p += 8;
                        v2 = xxh64_round(v2, *(uint64_t *) p);
                        p += 8;
                        v3 = xxh64_round(v3, *(uint64_t *) p);
                        p += 8;
                        v4 = xxh64_round(v4, *(uint64_t *) p);
                        p += 8;
                };

                h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) +
                      XXH_rotl64(v4, 18);
                h64 = xxh64_merge_round(h64, v1);
                h64 = xxh64_merge_round(h64, v2);
                h64 = xxh64_merge_round(h64, v3);
                h64 = xxh64_merge_round(h64, v4);
        } else
                h64 = ctx->job.digest[2] + PRIME64_5;

        h64 += ctx->total_length;

        while (p + 8 <= b_end) {
                const uint64_t k1 = xxh64_round(0, *(uint64_t *) p);

                h64 ^= k1;
                h64 = XXH_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
                p += 8;
        }

        if (p + 4 <= b_end) {
                h64 ^= (uint64_t) (*(uint32_t *) p) * PRIME64_1;
                h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
                p += 4;
        }

        while (p < b_end) {
                h64 ^= (*p) * PRIME64_5;
                h64 = XXH_rotl64(h64, 11) * PRIME64_1;
                p++;
        }

        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;

        ctx->job.result_digest = h64;
}
