/**********************************************************************
  Copyright(c) 2024 Intel Corporation All rights reserved.

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

#ifndef _SHA512_MB_INTERNAL_H_
#define _SHA512_MB_INTERNAL_H_

/**
 *  @file sha512_mb_internal.h
 *  @brief Multi-buffer CTX API function prototypes and structures
 *
 */

#include <stdint.h>
#include <string.h>

#include "sha512_mb.h"
#include "multi_buffer.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_X4_LANES            4
#define SHA512_LOG2_BLOCK_SIZE     7
#define SHA512_INITIAL_DIGEST                                                                      \
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,            \
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

/*******************************************************************
 * Context level API function prototypes
 ******************************************************************/

/**
 * @brief Initialize the context level SHA512 multi-buffer manager structure.
 * @requires SSE4.1
 *
 * @param mgr Structure holding context level state info
 * @returns void
 */
void
_sha512_ctx_mgr_init_sse(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the context level multi-buffer manager.
 * @requires SSE4.1
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_submit_sse(SHA512_HASH_CTX_MGR *mgr, SHA512_HASH_CTX *ctx, const void *buffer,
                           uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires SSE4.1
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_flush_sse(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires AVX
 *
 * @param mgr Structure holding context level state info
 * @returns void
 */
void
_sha512_ctx_mgr_init_avx(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires AVX
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_submit_avx(SHA512_HASH_CTX_MGR *mgr, SHA512_HASH_CTX *ctx, const void *buffer,
                           uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires AVX
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_flush_avx(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires AVX2
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
_sha512_ctx_mgr_init_avx2(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires AVX2
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_submit_avx2(SHA512_HASH_CTX_MGR *mgr, SHA512_HASH_CTX *ctx, const void *buffer,
                            uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires AVX2
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_flush_avx2(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires AVX512
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
_sha512_ctx_mgr_init_avx512(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires AVX512
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_submit_avx512(SHA512_HASH_CTX_MGR *mgr, SHA512_HASH_CTX *ctx, const void *buffer,
                              uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires AVX512
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_flush_avx512(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires SSE4
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
_sha512_ctx_mgr_init_sb_sse4(SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires SSE4
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_submit_sb_sse4(SHA512_HASH_CTX_MGR *mgr, SHA512_HASH_CTX *ctx, const void *buffer,
                               uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires SSE4
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
SHA512_HASH_CTX *
_sha512_ctx_mgr_flush_sb_sse4(SHA512_HASH_CTX_MGR *mgr);

/*******************************************************************
 * Scheduler (internal) level out-of-order function prototypes
 ******************************************************************/

void
_sha512_mb_mgr_init_sse(SHA512_MB_JOB_MGR *state);
SHA512_JOB *
_sha512_mb_mgr_submit_sse(SHA512_MB_JOB_MGR *state, SHA512_JOB *job);
SHA512_JOB *
_sha512_mb_mgr_flush_sse(SHA512_MB_JOB_MGR *state);

#define _sha512_mb_mgr_init_avx _sha512_mb_mgr_init_sse
SHA512_JOB *
_sha512_mb_mgr_submit_avx(SHA512_MB_JOB_MGR *state, SHA512_JOB *job);
SHA512_JOB *
_sha512_mb_mgr_flush_avx(SHA512_MB_JOB_MGR *state);

void
_sha512_mb_mgr_init_avx2(SHA512_MB_JOB_MGR *state);
SHA512_JOB *
_sha512_mb_mgr_submit_avx2(SHA512_MB_JOB_MGR *state, SHA512_JOB *job);
SHA512_JOB *
_sha512_mb_mgr_flush_avx2(SHA512_MB_JOB_MGR *state);

void
_sha512_mb_mgr_init_avx512(SHA512_MB_JOB_MGR *state);
SHA512_JOB *
_sha512_mb_mgr_submit_avx512(SHA512_MB_JOB_MGR *state, SHA512_JOB *job);
SHA512_JOB *
_sha512_mb_mgr_flush_avx512(SHA512_MB_JOB_MGR *state);

// Single buffer SHA512 APIs, optimized for SLM.
void
_sha512_sse4(const void *M, void *D, uint64_t L);
// Note that these APIs comply with multi-buffer APIs' high level usage
void
_sha512_sb_mgr_init_sse4(SHA512_MB_JOB_MGR *state);
SHA512_JOB *
_sha512_sb_mgr_submit_sse4(SHA512_MB_JOB_MGR *state, SHA512_JOB *job);
SHA512_JOB *
_sha512_sb_mgr_flush_sse4(SHA512_MB_JOB_MGR *state);
#ifdef __cplusplus
}
#endif

#endif // _SHA512_MB_INTERNAL_H_
