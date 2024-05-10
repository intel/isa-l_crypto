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

#ifndef _MD5_MB_INTERNAL_H_
#define _MD5_MB_INTERNAL_H_

/**
 *  @file md5_mb_internal.h
 *  @brief Multi-buffer CTX API MD5 function prototypes and structures
 */

#include <stdint.h>
#include <string.h>

#include "md5_mb.h"
#include "multi_buffer.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************
 * CTX level API function prototypes
 ******************************************************************/

/**
 * @brief Initialize the context level MD5 multi-buffer manager structure.
 * @requires SSE4.1
 *
 * @param mgr Structure holding context level state info
 * @returns void
 */
void
_md5_ctx_mgr_init_sse(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new MD5 job to the context level multi-buffer manager.
 * @requires SSE4.1
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_submit_sse(MD5_HASH_CTX_MGR *mgr, MD5_HASH_CTX *ctx, const void *buffer, uint32_t len,
                        ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted MD5 jobs and return when complete.
 * @requires SSE4.1
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_flush_sse(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the MD5 multi-buffer manager structure.
 * @requires AVX
 *
 * @param mgr Structure holding context level state info
 * @returns void
 */
void
_md5_ctx_mgr_init_avx(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new MD5 job to the multi-buffer manager.
 * @requires AVX
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_submit_avx(MD5_HASH_CTX_MGR *mgr, MD5_HASH_CTX *ctx, const void *buffer, uint32_t len,
                        ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted MD5 jobs and return when complete.
 * @requires AVX
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_flush_avx(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the MD5 multi-buffer manager structure.
 * @requires AVX2
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
_md5_ctx_mgr_init_avx2(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new MD5 job to the multi-buffer manager.
 * @requires AVX2
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_submit_avx2(MD5_HASH_CTX_MGR *mgr, MD5_HASH_CTX *ctx, const void *buffer, uint32_t len,
                         ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted MD5 jobs and return when complete.
 * @requires AVX2
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_flush_avx2(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the MD5 multi-buffer manager structure.
 * @requires AVX512
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
_md5_ctx_mgr_init_avx512(MD5_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new MD5 job to the multi-buffer manager.
 * @requires AVX512
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_submit_avx512(MD5_HASH_CTX_MGR *mgr, MD5_HASH_CTX *ctx, const void *buffer,
                           uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted MD5 jobs and return when complete.
 * @requires AVX512
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
MD5_HASH_CTX *
_md5_ctx_mgr_flush_avx512(MD5_HASH_CTX_MGR *mgr);

/*******************************************************************
 * Scheduler (internal) level out-of-order function prototypes
 ******************************************************************/

void
_md5_mb_mgr_init_sse(MD5_MB_JOB_MGR *state);
MD5_JOB *
_md5_mb_mgr_submit_sse(MD5_MB_JOB_MGR *state, MD5_JOB *job);
MD5_JOB *
_md5_mb_mgr_flush_sse(MD5_MB_JOB_MGR *state);

#define _md5_mb_mgr_init_avx _md5_mb_mgr_init_sse
MD5_JOB *
_md5_mb_mgr_submit_avx(MD5_MB_JOB_MGR *state, MD5_JOB *job);
MD5_JOB *
_md5_mb_mgr_flush_avx(MD5_MB_JOB_MGR *state);

void
_md5_mb_mgr_init_avx2(MD5_MB_JOB_MGR *state);
MD5_JOB *
_md5_mb_mgr_submit_avx2(MD5_MB_JOB_MGR *state, MD5_JOB *job);
MD5_JOB *
_md5_mb_mgr_flush_avx2(MD5_MB_JOB_MGR *state);

void
_md5_mb_mgr_init_avx512(MD5_MB_JOB_MGR *state);
MD5_JOB *
_md5_mb_mgr_submit_avx512(MD5_MB_JOB_MGR *state, MD5_JOB *job);
MD5_JOB *
_md5_mb_mgr_flush_avx512(MD5_MB_JOB_MGR *state);

#ifdef __cplusplus
}
#endif

#endif // _MD5_MB_INTERNAL_H_
