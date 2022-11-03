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
#include <stdlib.h>
#include "xxhash_mb.h"
#include "memcpy_inline.h"
#include <stdio.h>

#define PRIME32_1 0x9E3779B1U
#define PRIME32_2 0x85EBCA77U
#define PRIME32_3 0xC2B2AE3DU
#define PRIME32_4 0x27D4EB2FU
#define PRIME32_5 0x165667B1U

#define PRIME64_1 0x9E3779B185EBCA87ULL
#define PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define PRIME64_3 0x165667B19E3779F9ULL
#define PRIME64_4 0x85EBCA77C2B2AE63ULL
#define PRIME64_5 0x27D4EB2F165667C5ULL

#define XXH_rotl32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_rotl64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

extern void
xxh32_mb_mgr_init_sve(XXH32_MB_JOB_MGR *state);
extern XXH32_JOB *
xxh32_mb_mgr_submit_sve(XXH32_MB_JOB_MGR *state, XXH32_JOB *job);
extern XXH32_JOB *
xxh32_mb_mgr_flush_sve(XXH32_MB_JOB_MGR *state);

static XXH32_HASH_CTX *
xxh32_ctx_mgr_resubmit(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx);
extern void
xxh64_mb_mgr_init_sve(XXH64_MB_JOB_MGR *state);
extern XXH64_JOB *
xxh64_mb_mgr_submit_sve(XXH64_MB_JOB_MGR *state, XXH64_JOB *job);
extern XXH64_JOB *
xxh64_mb_mgr_flush_sve(XXH64_MB_JOB_MGR *state);

extern void
dump_state(XXH32_MB_JOB_MGR *state);

static uint32_t
xxh32_round(uint32_t seed, const uint32_t input)
{
        seed += input * PRIME32_2;
        seed = XXH_rotl32(seed, 13);
        seed *= PRIME32_1;
        return seed;
}

static inline void
xxh32_hash_init_digest(XXH32_HASH_CTX *ctx)
{
        ctx->job.digest[0] = ctx->seed + PRIME32_1 + PRIME32_2;
        ctx->job.digest[1] = ctx->seed + PRIME32_2;
        ctx->job.digest[2] = ctx->seed;
        ctx->job.digest[3] = ctx->seed - PRIME32_1;
}

static inline uint32_t
hash_pad(uint8_t padblock[XXH32_BLOCK_SIZE * 2], uint64_t total_len)
{
        return 0;
}

void
xxh32_ctx_mgr_init_sve(XXH32_HASH_CTX_MGR *mgr)
{
        xxh32_mb_mgr_init_sve(&mgr->mgr);
}

static void
xxh32_ctx_get_hash(XXH32_HASH_CTX *ctx, const void *buffer, uint32_t len)
{
        const uint8_t *p = (const uint8_t *) buffer;
        const uint8_t *b_end = p + len;
        uint32_t h32;

        if (len >= 16) {
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
                h32 = XXH_rotl32(ctx->job.digest[0], 1) + XXH_rotl32(ctx->job.digest[1], 7) +
                      XXH_rotl32(ctx->job.digest[2], 12) + XXH_rotl32(ctx->job.digest[3], 18);
        } else if ((len % 16 < 16) && (ctx->total_length >= 256)) {
                h32 = XXH_rotl32(ctx->job.digest[0], 1) + XXH_rotl32(ctx->job.digest[1], 7) +
                      XXH_rotl32(ctx->job.digest[2], 12) + XXH_rotl32(ctx->job.digest[3], 18);
        } else
                h32 = ctx->job.result_digest;

        h32 += ctx->total_length;

        while (p + 4 <= b_end) {
                h32 += *(uint32_t *) p * PRIME32_3;
                h32 = XXH_rotl32(h32, 17) * PRIME32_4;
                p += 4;
        }

        while (p < b_end) {
                h32 += (*p) * PRIME32_5;
                h32 = XXH_rotl32(h32, 11) * PRIME32_1;
                p++;
        }

        h32 ^= h32 >> 15;
        h32 *= PRIME32_2;
        h32 ^= h32 >> 13;
        h32 *= PRIME32_3;
        h32 ^= h32 >> 16;
        ctx->job.result_digest = h32;
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_submit_sve(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx, const void *buffer,
                         uint32_t len, HASH_CTX_FLAG flags)
{
        if (flags & (~HASH_ENTIRE)) {
                ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
                return ctx;
        }

        if (ctx->status & HASH_CTX_STS_PROCESSING) {
                // Cannot submit to a currently processing job.
                ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_COMPLETE) && !(flags & HASH_FIRST)) {
                // Cannot update a finished job.
                ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
                return ctx;
        }

        if (flags & HASH_FIRST) {
                // Init digest
                xxh32_hash_init_digest(ctx);

                // Reset byte counter
                ctx->total_length = 0;

                // Clear extra blocks
                ctx->partial_block_buffer_length = 0;
                ctx->region_start = (uint64_t) buffer;
                ctx->region_end = (uint64_t) buffer + len - 4;
                if (!mgr->mgr.region_start && !mgr->mgr.region_end) {
                        mgr->mgr.region_start = ctx->region_start;
                        mgr->mgr.region_end = ctx->region_end;
                } else {
                        if (mgr->mgr.region_start > ctx->region_start)
                                mgr->mgr.region_start = ctx->region_start;
                        if (mgr->mgr.region_end < ctx->region_end)
                                mgr->mgr.region_end = ctx->region_end;
                }
        }
        // If we made it here, there were no errors during this call to submit
        ctx->error = HASH_CTX_ERROR_NONE;

        // Store buffer ptr info from user
        ctx->incoming_buffer = buffer;
        ctx->incoming_buffer_length = len;

        // Store the user's request flags and mark this ctx as currently being
        // processed.
        ctx->status = (flags & HASH_LAST)
                              ? (HASH_CTX_STS) (HASH_CTX_STS_PROCESSING | HASH_CTX_STS_LAST)
                              : HASH_CTX_STS_PROCESSING;

        // Advance byte counter
        ctx->total_length += len;

        // If there is anything currently buffered in the extra blocks, append
        // to it until it contains a whole block.
        // Or if the user's buffer contains less than a whole block, append as
        // much as possible to the extra block.
        if ((ctx->partial_block_buffer_length) | (len < XXH32_BLOCK_SIZE)) {
                // Compute how many bytes to copy from user buffer into extra
                // block
                uint32_t copy_len;

                copy_len = XXH32_BLOCK_SIZE - ctx->partial_block_buffer_length;
                if (len < copy_len)
                        copy_len = len;

                if (copy_len) {
                        // Copy and update relevant pointers and counters
                        memcpy_varlen(&ctx->partial_block_buffer[ctx->partial_block_buffer_length],
                                      buffer, copy_len);

                        ctx->partial_block_buffer_length += copy_len;
                        ctx->incoming_buffer = (const void *) ((uint64_t) buffer + copy_len);
                        ctx->incoming_buffer_length = len - copy_len;
                }
                // The extra block should never contain more than 1 block here
                assert(ctx->partial_block_buffer_length <= XXH32_BLOCK_SIZE);
                // If the extra block buffer contains exactly 1 block, it can
                // be hashed.
                if (ctx->partial_block_buffer_length >= XXH32_BLOCK_SIZE) {
                        ctx->partial_block_buffer_length = 0;

                        ctx->job.buffer = ctx->partial_block_buffer;
                        ctx->job.blk_len = 1;
                        ctx = (XXH32_HASH_CTX *) xxh32_mb_mgr_submit_sve(&mgr->mgr, &ctx->job);
                }
        }

        return xxh32_ctx_mgr_resubmit(mgr, ctx);
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_flush_sve(XXH32_HASH_CTX_MGR *mgr)
{
        XXH32_HASH_CTX *ctx;

        while (1) {
                ctx = (XXH32_HASH_CTX *) xxh32_mb_mgr_flush_sve(&mgr->mgr);

                // If flush returned 0, there are no more jobs in flight.
                if (!ctx)
                        return NULL;

                // If flush returned a job, verify that it is safe to return to the user.
                // If it is not ready, resubmit the job to finish processing.
                ctx = xxh32_ctx_mgr_resubmit(mgr, ctx);

                // If xxh32_ctx_mgr_resubmit returned a job, it is ready to be returned.
                if (ctx)
                        return ctx;

                // Otherwise, all jobs currently being managed by the HASH_CTX_MGR still need
                // processing. Loop.
        }
}

static XXH32_HASH_CTX *
xxh32_ctx_mgr_resubmit(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx)
{
        while (ctx) {
                if (ctx->status & HASH_CTX_STS_COMPLETE) {
                        // Clear PROCESSING bit
                        ctx->status = HASH_CTX_STS_COMPLETE;
                        return ctx;
                }
                // If the extra blocks are empty, begin hashing what remains
                // in the user's buffer.
                if (ctx->partial_block_buffer_length == 0 && ctx->incoming_buffer_length) {
                        const void *buffer = ctx->incoming_buffer;
                        uint32_t len = ctx->incoming_buffer_length;

                        // Only entire blocks can be hashed. Copy remainder to
                        // extra blocks buffer.
                        uint32_t copy_len = len & (XXH32_BLOCK_SIZE - 1);

                        if (copy_len) {
                                len -= copy_len;
                                memcpy_varlen(ctx->partial_block_buffer,
                                              ((const char *) buffer + len), copy_len);
                                ctx->partial_block_buffer_length = copy_len;
                        }

                        ctx->incoming_buffer_length = 0;

                        // len should be a multiple of the block size now
                        assert((len % XXH32_BLOCK_SIZE) == 0);

                        if (len) {
                                ctx->job.buffer = (uint8_t *) buffer;
                                ctx->job.blk_len = len >> XXH32_LOG2_BLOCK_SIZE;
                                ctx = (XXH32_HASH_CTX *) xxh32_mb_mgr_submit_sve(&mgr->mgr,
                                                                                 &ctx->job);
                                continue;
                        }
                }
                // If the extra blocks are not empty, then we are either on the
                // last block(s) or we need more user input before continuing.
                if (ctx->status & HASH_CTX_STS_LAST) {

                        uint8_t *buf = ctx->partial_block_buffer;
                        // uint32_t n_extra_blocks = hash_pad(buf, ctx->total_length);

                        ctx->status = HASH_CTX_STS_PROCESSING | HASH_CTX_STS_COMPLETE;

                        ctx->job.buffer = buf;
                        if (ctx->total_length < 16) {
                                // Don't use ctx->job.digest[].
                                ctx->job.result_digest = ctx->seed + PRIME32_5;
                                xxh32_ctx_get_hash(ctx, buf, ctx->partial_block_buffer_length);
                        } else {
                                if (ctx->total_length < XXH32_BLOCK_SIZE)
                                        xxh32_ctx_get_hash(ctx, buf,
                                                           ctx->partial_block_buffer_length);
                                else {
                                        ctx = (XXH32_HASH_CTX *) xxh32_mb_mgr_submit_sve(&mgr->mgr,
                                                                                         &ctx->job);
                                        xxh32_ctx_get_hash(ctx, buf,
                                                           ctx->partial_block_buffer_length);
                                }
                        }
                        continue;
                }

                if (ctx)
                        ctx->status = HASH_CTX_STS_IDLE;
                return ctx;
        }

        return NULL;
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

static inline void
xxh64_hash_init_digest(XXH64_HASH_CTX *ctx)
{
        ctx->job.digest[0] = ctx->seed + PRIME64_1 + PRIME64_2;
        ctx->job.digest[1] = ctx->seed + PRIME64_2;
        ctx->job.digest[2] = ctx->seed;
        ctx->job.digest[3] = ctx->seed - PRIME64_1;
}

void
xxh64_ctx_mgr_init_sve(XXH64_HASH_CTX_MGR *mgr)
{
        xxh64_mb_mgr_init_sve(&mgr->mgr);
}

static void
xxh64_ctx_get_hash(XXH64_HASH_CTX *ctx, const void *buffer, uint32_t len)
{
        const uint8_t *p = (const uint8_t *) buffer;
        const uint8_t *b_end = p + len;
        uint64_t h64;

        if (len >= 32) {
                const uint8_t *const limit = b_end - 32;

                do {
                        ctx->job.digest[0] = xxh64_round(ctx->job.digest[0], *(uint64_t *) p);
                        p += 8;
                        ctx->job.digest[1] = xxh64_round(ctx->job.digest[1], *(uint64_t *) p);
                        p += 8;
                        ctx->job.digest[2] = xxh64_round(ctx->job.digest[2], *(uint64_t *) p);
                        p += 8;
                        ctx->job.digest[3] = xxh64_round(ctx->job.digest[3], *(uint64_t *) p);
                        p += 8;
                } while (p <= limit);
                h64 = XXH_rotl64(ctx->job.digest[0], 1) + XXH_rotl64(ctx->job.digest[1], 7) +
                      XXH_rotl64(ctx->job.digest[2], 12) + XXH_rotl64(ctx->job.digest[3], 18);
                h64 = xxh64_merge_round(h64, ctx->job.digest[0]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[1]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[2]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[3]);
        } else if ((len % 32 < 32) && (ctx->total_length >= 256)) {
                h64 = XXH_rotl64(ctx->job.digest[0], 1) + XXH_rotl64(ctx->job.digest[1], 7) +
                      XXH_rotl64(ctx->job.digest[2], 12) + XXH_rotl64(ctx->job.digest[3], 18);
                h64 = xxh64_merge_round(h64, ctx->job.digest[0]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[1]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[2]);
                h64 = xxh64_merge_round(h64, ctx->job.digest[3]);
        } else
                h64 = ctx->job.result_digest;

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

static XXH64_HASH_CTX *
xxh64_ctx_mgr_resubmit(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx)
{
        while (ctx) {
                if (ctx->status & HASH_CTX_STS_COMPLETE) {
                        // Clear PROCESSING bit
                        ctx->status = HASH_CTX_STS_COMPLETE;
                        return ctx;
                }
                // If the extra blocks are empty, begin hashing what remains
                // in the user's buffer.
                if (ctx->partial_block_buffer_length == 0 && ctx->incoming_buffer_length) {
                        const void *buffer = ctx->incoming_buffer;
                        size_t len = ctx->incoming_buffer_length;

                        // Only entire blocks can be hashed. Copy remainder to
                        // extra blocks buffer.
                        size_t copy_len = len & (XXH64_BLOCK_SIZE - 1);
                        if (copy_len) {
                                len -= copy_len;
                                memcpy_varlen(ctx->partial_block_buffer,
                                              ((const char *) buffer + len), copy_len);
                                ctx->partial_block_buffer_length = copy_len;
                        }
                        ctx->incoming_buffer_length = 0;

                        // len should be a multiple of the block size now
                        assert((len % XXH64_BLOCK_SIZE) == 0);

                        if (len) {
                                ctx->job.buffer = (uint8_t *) buffer;
                                ctx->job.blk_len = len >> XXH64_LOG2_BLOCK_SIZE;
                                ctx = (XXH64_HASH_CTX *) xxh64_mb_mgr_submit_sve(&mgr->mgr,
                                                                                 &ctx->job);
                                continue;
                        }
                }
                // If the extra blocks are not empty, then we are either on the
                // last block(s) or we need more user input before continuing.
                if (ctx->status & HASH_CTX_STS_LAST) {
                        uint8_t *buf = ctx->partial_block_buffer;

                        ctx->status = HASH_CTX_STS_PROCESSING | HASH_CTX_STS_COMPLETE;

                        ctx->job.buffer = buf;
                        if (ctx->total_length < 32) {
                                // Don't use ctx->job.digest[].
                                ctx->job.result_digest = ctx->seed + PRIME64_5;
                                xxh64_ctx_get_hash(ctx, buf, ctx->partial_block_buffer_length);
                        } else {
                                if (ctx->total_length < XXH64_BLOCK_SIZE)
                                        xxh64_ctx_get_hash(ctx, buf,
                                                           ctx->partial_block_buffer_length);
                                else {
                                        ctx = (XXH64_HASH_CTX *) xxh64_mb_mgr_submit_sve(&mgr->mgr,
                                                                                         &ctx->job);
                                        xxh64_ctx_get_hash(ctx, buf,
                                                           ctx->partial_block_buffer_length);
                                }
                        }
                        continue;
                }

                if (ctx)
                        ctx->status = HASH_CTX_STS_IDLE;
                return ctx;
        }
        return NULL;
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_submit_sve(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx, const void *buffer,
                         size_t len, HASH_CTX_FLAG flags)
{
        if (flags & (~HASH_ENTIRE)) {
                ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
                return ctx;
        }

        if (ctx->status & HASH_CTX_STS_PROCESSING) {
                // Cannot submit to a currently processing job.
                ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
                return ctx;
        }

        if ((ctx->status & HASH_CTX_STS_COMPLETE) && (!flags & HASH_FIRST)) {
                // Cannot update a finished job.
                ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
                return ctx;
        }

        if (flags & HASH_FIRST) {
                // Init digest
                xxh64_hash_init_digest(ctx);

                // Reset byte counter;
                ctx->total_length = 0;

                // Clear extra blocks
                ctx->partial_block_buffer_length = 0;
        }
        // If we made it here, there were no errors during this call to submit
        ctx->error = HASH_CTX_ERROR_NONE;

        // Store buffer ptr info from user
        ctx->incoming_buffer = buffer;
        ctx->incoming_buffer_length = len;

        // Store the user's request flags and mark this ctx as currently being
        // processed.
        ctx->status = (flags & HASH_LAST)
                              ? (HASH_CTX_STS) (HASH_CTX_STS_PROCESSING | HASH_CTX_STS_LAST)
                              : HASH_CTX_STS_PROCESSING;

        // Advance byte counter
        ctx->total_length += len;

        // If there is anything currently buffered in the extra blocks, append
        // to it until it contains a whole block.
        // Or if the user's buffer contains less than a whole block, append as
        // much as possible to the extra block.
        if ((ctx->partial_block_buffer_length) | (len < XXH64_BLOCK_SIZE)) {
                // Compute how many bytes to copy from user buffer into extra
                // block
                size_t copy_len;

                copy_len = XXH64_BLOCK_SIZE - ctx->partial_block_buffer_length;
                if (len < copy_len)
                        copy_len = len;

                if (copy_len) {
                        // Copy and update relevant pointers and counters
                        memcpy_varlen(&ctx->partial_block_buffer[ctx->partial_block_buffer_length],
                                      buffer, copy_len);
                        ctx->partial_block_buffer_length += copy_len;
                        ctx->incoming_buffer = (const void *) ((uint64_t) buffer + copy_len);
                        ctx->incoming_buffer_length = len - copy_len;
                }
                // The extra block should never contain more than 1 block here
                assert(ctx->partial_block_buffer_length <= XXH64_BLOCK_SIZE);
                // If the extra block buffer contains exactly 1 block, it can
                // be hashed.
                if (ctx->partial_block_buffer_length >= XXH64_BLOCK_SIZE) {
                        ctx->partial_block_buffer_length = 0;
                        ctx->job.buffer = ctx->partial_block_buffer;
                        ctx->job.blk_len = 1;
                        ctx = (XXH64_HASH_CTX *) xxh64_mb_mgr_submit_sve(&mgr->mgr, &ctx->job);
                }
        }
        return xxh64_ctx_mgr_resubmit(mgr, ctx);
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_flush_sve(XXH64_HASH_CTX_MGR *mgr)
{
        XXH64_HASH_CTX *ctx;

        while (1) {
                ctx = (XXH64_HASH_CTX *) xxh64_mb_mgr_flush_sve(&mgr->mgr);
                // If flush returned 0, there are no more jobs in flight.
                if (!ctx)
                        return NULL;

                // If flush returned a job, verify that it is safe to return to the user.
                // If it is not ready, resubmit the job to finish processing.
                ctx = xxh64_ctx_mgr_resubmit(mgr, ctx);
                // If xxh64_ctx_mgr_resubmit returned a job, it is ready to be returned.
                if (ctx)
                        return ctx;
                // Otherwise, all jobs currently being managed by the HASH_CTX_MGR still need
                // processing. Loop.
        }
}
