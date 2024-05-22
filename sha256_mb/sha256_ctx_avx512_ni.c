/**********************************************************************
  Copyright(c) 2011-2017 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
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

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#elif defined(__ICC)
#pragma intel optimization_parameter target_arch = AVX2
#elif defined(__ICL)
#pragma[intel] optimization_parameter target_arch = AVX2
#elif (__GNUC__ >= 5)
#pragma GCC target("avx2")
#endif

#include "sha256_mb_internal.h"
#include "memcpy_inline.h"
#include "endian_helper.h"

#ifdef _MSC_VER
#include <intrin.h>
#define inline __inline
#endif

/**
 *  sha256_ctx_avx512_ni related functions are aiming to utilize Canon Lake.
 *  Since SHANI is still slower than multibuffer for full lanes,
 *  _sha256_ctx_mgr_init_avx512_ni and _sha256_ctx_mgr_submit_avx512_ni are
 *  similar with their avx512 versions.
 *  _sha256_ctx_mgr_flush_avx512_ni is different. It will call
 *  _sha256_mb_mgr_flush_avx512_ni which would use shani when lanes are less
 *  than a threshold.
 *
 */

static inline void
hash_init_digest(ISAL_SHA256_WORD_T *digest);
static inline uint32_t
hash_pad(uint8_t padblock[ISAL_SHA256_BLOCK_SIZE * 2], uint64_t total_len);
static ISAL_SHA256_HASH_CTX *
sha256_ctx_mgr_resubmit(ISAL_SHA256_HASH_CTX_MGR *mgr, ISAL_SHA256_HASH_CTX *ctx);

void
_sha256_ctx_mgr_init_avx512_ni(ISAL_SHA256_HASH_CTX_MGR *mgr)
{
        _sha256_mb_mgr_init_avx512(&mgr->mgr);
}

ISAL_SHA256_HASH_CTX *
_sha256_ctx_mgr_submit_avx512_ni(ISAL_SHA256_HASH_CTX_MGR *mgr, ISAL_SHA256_HASH_CTX *ctx,
                                 const void *buffer, uint32_t len, ISAL_HASH_CTX_FLAG flags)
{
        if (flags & (~ISAL_HASH_ENTIRE)) {
                // User should not pass anything other than FIRST, UPDATE, or LAST
                ctx->error = ISAL_HASH_CTX_ERROR_INVALID_FLAGS;
                return ctx;
        }

        if (ctx->status & ISAL_HASH_CTX_STS_PROCESSING) {
                // Cannot submit to a currently processing job.
                ctx->error = ISAL_HASH_CTX_ERROR_ALREADY_PROCESSING;
                return ctx;
        }

        if ((ctx->status & ISAL_HASH_CTX_STS_COMPLETE) && !(flags & ISAL_HASH_FIRST)) {
                // Cannot update a finished job.
                ctx->error = ISAL_HASH_CTX_ERROR_ALREADY_COMPLETED;
                return ctx;
        }

        if (flags & ISAL_HASH_FIRST) {
                // Init digest
                hash_init_digest(ctx->job.result_digest);

                // Reset byte counter
                ctx->total_length = 0;

                // Clear extra blocks
                ctx->partial_block_buffer_length = 0;
        }
        // If we made it here, there were no errors during this call to submit
        ctx->error = ISAL_HASH_CTX_ERROR_NONE;

        // Store buffer ptr info from user
        ctx->incoming_buffer = buffer;
        ctx->incoming_buffer_length = len;

        // Store the user's request flags and mark this ctx as currently being processed.
        ctx->status = (flags & ISAL_HASH_LAST) ? (ISAL_HASH_CTX_STS) (ISAL_HASH_CTX_STS_PROCESSING |
                                                                      ISAL_HASH_CTX_STS_LAST)
                                               : ISAL_HASH_CTX_STS_PROCESSING;

        // Advance byte counter
        ctx->total_length += len;

        // If there is anything currently buffered in the extra blocks, append to it until it
        // contains a whole block. Or if the user's buffer contains less than a whole block, append
        // as much as possible to the extra block.
        if ((ctx->partial_block_buffer_length) | (len < ISAL_SHA256_BLOCK_SIZE)) {
                // Compute how many bytes to copy from user buffer into extra block
                uint32_t copy_len = ISAL_SHA256_BLOCK_SIZE - ctx->partial_block_buffer_length;
                if (len < copy_len)
                        copy_len = len;

                if (copy_len) {
                        // Copy and update relevant pointers and counters
                        memcpy_varlen(&ctx->partial_block_buffer[ctx->partial_block_buffer_length],
                                      buffer, copy_len);

                        ctx->partial_block_buffer_length += copy_len;
                        ctx->incoming_buffer = (const void *) ((const char *) buffer + copy_len);
                        ctx->incoming_buffer_length = len - copy_len;
                }
                // The extra block should never contain more than 1 block here
                assert(ctx->partial_block_buffer_length <= ISAL_SHA256_BLOCK_SIZE);

                // If the extra block buffer contains exactly 1 block, it can be hashed.
                if (ctx->partial_block_buffer_length >= ISAL_SHA256_BLOCK_SIZE) {
                        ctx->partial_block_buffer_length = 0;

                        ctx->job.buffer = ctx->partial_block_buffer;
                        ctx->job.len = 1;
                        ctx = (ISAL_SHA256_HASH_CTX *) _sha256_mb_mgr_submit_avx512(&mgr->mgr,
                                                                                    &ctx->job);
                }
        }

        return sha256_ctx_mgr_resubmit(mgr, ctx);
}

ISAL_SHA256_HASH_CTX *
_sha256_ctx_mgr_flush_avx512_ni(ISAL_SHA256_HASH_CTX_MGR *mgr)
{
        ISAL_SHA256_HASH_CTX *ctx;

        while (1) {
                ctx = (ISAL_SHA256_HASH_CTX *) _sha256_mb_mgr_flush_avx512_ni(&mgr->mgr);

                // If flush returned 0, there are no more jobs in flight.
                if (!ctx)
                        return NULL;

                // If flush returned a job, verify that it is safe to return to the user.
                // If it is not ready, resubmit the job to finish processing.
                ctx = sha256_ctx_mgr_resubmit(mgr, ctx);

                // If sha256_ctx_mgr_resubmit returned a job, it is ready to be returned.
                if (ctx)
                        return ctx;

                // Otherwise, all jobs currently being managed by the ISAL_SHA256_HASH_CTX_MGR still
                // need processing. Loop.
        }
}

static ISAL_SHA256_HASH_CTX *
sha256_ctx_mgr_resubmit(ISAL_SHA256_HASH_CTX_MGR *mgr, ISAL_SHA256_HASH_CTX *ctx)
{
        while (ctx) {
                if (ctx->status & ISAL_HASH_CTX_STS_COMPLETE) {
                        ctx->status = ISAL_HASH_CTX_STS_COMPLETE; // Clear PROCESSING bit
                        return ctx;
                }
                // If the extra blocks are empty, begin hashing what remains in the user's buffer.
                if (ctx->partial_block_buffer_length == 0 && ctx->incoming_buffer_length) {
                        const void *buffer = ctx->incoming_buffer;
                        uint32_t len = ctx->incoming_buffer_length;

                        // Only entire blocks can be hashed. Copy remainder to extra blocks buffer.
                        uint32_t copy_len = len & (ISAL_SHA256_BLOCK_SIZE - 1);

                        if (copy_len) {
                                len -= copy_len;
                                memcpy_varlen(ctx->partial_block_buffer,
                                              ((const char *) buffer + len), copy_len);
                                ctx->partial_block_buffer_length = copy_len;
                        }

                        ctx->incoming_buffer_length = 0;

                        // len should be a multiple of the block size now
                        assert((len % ISAL_SHA256_BLOCK_SIZE) == 0);

                        // Set len to the number of blocks to be hashed in the user's buffer
                        len >>= ISAL_SHA256_LOG2_BLOCK_SIZE;

                        if (len) {
                                ctx->job.buffer = (uint8_t *) buffer;
                                ctx->job.len = len;
                                ctx = (ISAL_SHA256_HASH_CTX *) _sha256_mb_mgr_submit_avx512(
                                        &mgr->mgr, &ctx->job);
                                continue;
                        }
                }
                // If the extra blocks are not empty, then we are either on the last block(s)
                // or we need more user input before continuing.
                if (ctx->status & ISAL_HASH_CTX_STS_LAST) {
                        uint8_t *buf = ctx->partial_block_buffer;
                        uint32_t n_extra_blocks = hash_pad(buf, ctx->total_length);

                        ctx->status = (ISAL_HASH_CTX_STS) (ISAL_HASH_CTX_STS_PROCESSING |
                                                           ISAL_HASH_CTX_STS_COMPLETE);
                        ctx->job.buffer = buf;
                        ctx->job.len = (uint32_t) n_extra_blocks;
                        ctx = (ISAL_SHA256_HASH_CTX *) _sha256_mb_mgr_submit_avx512(&mgr->mgr,
                                                                                    &ctx->job);
                        continue;
                }

                if (ctx)
                        ctx->status = ISAL_HASH_CTX_STS_IDLE;
                return ctx;
        }

        return NULL;
}

static inline void
hash_init_digest(ISAL_SHA256_WORD_T *digest)
{
        static const ISAL_SHA256_WORD_T hash_initial_digest[ISAL_SHA256_DIGEST_NWORDS] = {
                ISAL_SHA256_INITIAL_DIGEST
        };
        memcpy_fixedlen(digest, hash_initial_digest, sizeof(hash_initial_digest));
}

static inline uint32_t
hash_pad(uint8_t padblock[ISAL_SHA256_BLOCK_SIZE * 2], uint64_t total_len)
{
        uint32_t i = (uint32_t) (total_len & (ISAL_SHA256_BLOCK_SIZE - 1));

        memclr_fixedlen(&padblock[i], ISAL_SHA256_BLOCK_SIZE);
        padblock[i] = 0x80;

        // Move i to the end of either 1st or 2nd extra block depending on length
        i += ((ISAL_SHA256_BLOCK_SIZE - 1) &
              (0 - (total_len + ISAL_SHA256_PADLENGTHFIELD_SIZE + 1))) +
             1 + ISAL_SHA256_PADLENGTHFIELD_SIZE;

#if ISAL_SHA256_PADLENGTHFIELD_SIZE == 16
        *((uint64_t *) &padblock[i - 16]) = 0;
#endif

        *((uint64_t *) &padblock[i - 8]) = to_be64((uint64_t) total_len << 3);

        return i >> ISAL_SHA256_LOG2_BLOCK_SIZE; // Number of extra blocks to hash
}

struct slver {
        uint16_t snum;
        uint8_t ver;
        uint8_t core;
};
struct slver _sha256_ctx_mgr_init_avx512_ni_slver_080002ca;
struct slver _sha256_ctx_mgr_init_avx512_ni_slver = { 0x02ca, 0x00, 0x08 };

struct slver _sha256_ctx_mgr_submit_avx512_ni_slver_080002cb;
struct slver _sha256_ctx_mgr_submit_avx512_ni_slver = { 0x02cb, 0x00, 0x08 };

struct slver _sha256_ctx_mgr_flush_avx512_ni_slver_080002cc;
struct slver _sha256_ctx_mgr_flush_avx512_ni_slver = { 0x02cc, 0x00, 0x08 };

#if defined(__clang__)
#pragma clang attribute pop
#endif
