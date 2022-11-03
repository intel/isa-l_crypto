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

#ifndef _XXHASH_MB_H_
#define _XXHASH_MB_H_

/*
 * For example, you would submit hashes with the following flags for the following numbers
 * of buffers:
 * <ul>
 *  <li> one buffer: HASH_FIRST | HASH_LAST  (or, equivalently, HASH_ENTIRE)
 *  <li> two buffers: HASH_FIRST, HASH_LAST
 *  <li> three buffers: HASH_FIRST, HASH_UPDATE, HASH_LAST
 * etc.
 * </ul>
 *
 */

#include <stdint.h>
#include "multi_buffer.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XXH32_DIGEST_NWORDS   4
#define XXH32_MAX_LANES       64  // for SVE2048
#define XXH32_BLOCK_SIZE      256 // for SVE2048
#define XXH32_LOG2_BLOCK_SIZE 8   // for SVE2048

#define XXH64_DIGEST_NDWORDS  4
#define XXH64_MAX_LANES       32  // for SVE2048
#define XXH64_BLOCK_SIZE      256 // for SVE2048
#define XXH64_LOG2_BLOCK_SIZE 8   // for SVE2048

typedef uint32_t xxh32_digest_array[XXH32_DIGEST_NWORDS][XXH32_MAX_LANES];
typedef uint64_t xxh64_digest_array[XXH64_DIGEST_NDWORDS][XXH64_MAX_LANES];

/** @brief Scheduler layer - Holds info describing a single XXH32 job for the
 *  multi-buffer manager
 */

typedef struct {
        uint8_t *buffer;  //!< pointer to data buffer for this job
        uint32_t blk_len; //!< length of buffer for this job in blocks.
        DECLARE_ALIGNED(uint32_t digest[XXH32_DIGEST_NWORDS * 4], 16);
        uint32_t result_digest; //!< final digest
        JOB_STS status;         //!< output job status
        void *user_data;        //!< pointer for user's job-related data
} XXH32_JOB;

/** @brief Scheduler layer -  Holds arguments for submitted XXH32 job */

typedef struct {
        xxh32_digest_array digest;
        uint8_t *data_ptr[XXH32_MAX_LANES];
} XXH32_MB_ARGS_X32;

/** @brief Scheduler layer - Lane data */

typedef struct {
        XXH32_JOB *job_in_lane;
} XXH32_LANE_DATA;

/** @brief Scheduler layer - Holds state for multi-buffer XXH32 jobs */

typedef struct {
        XXH32_MB_ARGS_X32 args;
        XXH32_LANE_DATA ldata[XXH32_MAX_LANES];
        /*
         * each byte is index (0...63) of unused lanes,
         * byte is set to 0x3F as a flag.
         */
        uint64_t unused_lanes[8];
        uint32_t lens[XXH32_MAX_LANES];
        /*
         * SVE vector could be vary among 128b, 256b, 512b, 1024b, 2048b.
         */
        uint32_t max_lanes_inuse;
        uint32_t num_lanes_inuse;
        uint64_t region_start;
        uint64_t region_end;
} XXH32_MB_JOB_MGR;

/** @brief Context layer - Holds state for multi-buffer XXH32 jobs */

typedef struct {
        XXH32_MB_JOB_MGR mgr;
} XXH32_HASH_CTX_MGR;

/** @brief Context layer - Holds state for multi-buffer XXH32 jobs */

/** @brief Context layer - Holds info describing a single XXH32 job for
 *  the multi-buffer CTX manager
 */

typedef struct {
        XXH32_JOB job;                   // Must be at struct offset 0.
        HASH_CTX_STS status;             //!< Context status flag
        HASH_CTX_ERROR error;            //!< Context error flag
        size_t total_length;             //!< Running counter of length processed for this CTX's job
        const void *incoming_buffer;     //!< pointer to data input buffer for this CTX's job
        uint32_t incoming_buffer_length; //!< length of buffer for this job in bytes.
        uint8_t partial_block_buffer[XXH32_BLOCK_SIZE * 2]; //!< CTX partial blocks
        uint32_t partial_block_buffer_length;
        uint64_t region_start; //!<
        uint64_t region_end;   //!<
        uint32_t large_len;    //!< Whether the hash is >=16
        uint32_t seed;         //!< Seed value
        void *user_data;       //!< pointer for user to keep any job-related data
} XXH32_HASH_CTX;

/** @brief Scheduler layer - Holds info describing a single XXH64 job for the
 *  multi-buffer manager
 */

typedef struct {
        uint8_t *buffer;  //!< pointer to data buffer for this job
        uint32_t blk_len; //!< length of buffer for this job in blocks.
        DECLARE_ALIGNED(uint64_t digest[XXH64_DIGEST_NDWORDS], 16);
        uint64_t result_digest; //!< final digest
        JOB_STS status;         //!< output job status
        void *user_data;        //!< pointer for user's job-related data
} XXH64_JOB;

/** @brief Scheduler layer -  Holds arguments for submitted XXH64 job */

typedef struct {
        xxh64_digest_array digest;
        uint8_t *data_ptr[XXH64_MAX_LANES];
} XXH64_MB_ARGS_X16;

/** @brief Scheduler layer - Lane data */

typedef struct {
        XXH64_JOB *job_in_lane;
} XXH64_LANE_DATA;

/** @brief Scheduler layer - Holds state for multi-buffer XXH64 jobs */

typedef struct {
        XXH64_MB_ARGS_X16 args;
        XXH64_LANE_DATA ldata[XXH64_MAX_LANES];
        /*
         * each nibble is index (0...31) of unused lanes,
         * nibble 4 or 8 is set to F as a flag.
         */
        uint64_t unused_lanes[4];
        uint32_t lens[XXH64_MAX_LANES];
        uint32_t max_lanes_inuse;
        uint32_t num_lanes_inuse;
} XXH64_MB_JOB_MGR;

/** @brief Context layer - Holds state for multi-buffer XXH64 jobs */

typedef struct {
        XXH64_MB_JOB_MGR mgr;
} XXH64_HASH_CTX_MGR;

/** @brief Context layer - Holds info describing a single XXH32 job for
 *  the multi-buffer CTX manager
 */

typedef struct {
        XXH64_JOB job;                   // Must be at struct offset 0.
        HASH_CTX_STS status;             //!< Context status flag
        HASH_CTX_ERROR error;            //!< Context error flag
        size_t total_length;             //!< Running counter of length processed for this CTX's job
        const void *incoming_buffer;     //!< pointer to data input buffer for this CTX's job
        uint32_t incoming_buffer_length; //!< length of buffer for this job in bytes.
        uint8_t partial_block_buffer[XXH64_BLOCK_SIZE * 2]; //!< CTX partial blocks
        uint32_t partial_block_buffer_length;
        uint64_t seed;   //!< Seed value
        void *user_data; //!< pointer for user to keep any job-related data
} XXH64_HASH_CTX;

/*******************************************************************
 * CTX level API function prototypes
 ******************************************************************/

/******************** multibinary function prototypes **********************/

/**
 * @brief Initialize the XXH32 multi-buffer manager structure.
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
xxh32_ctx_mgr_init(XXH32_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new XXH32 job to the multi-buffer manager.
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
XXH32_HASH_CTX *
xxh32_ctx_mgr_submit(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx, const void *buffer, uint32_t len,
                     HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted XXH32 jobs and return when complete.
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
XXH32_HASH_CTX *
xxh32_ctx_mgr_flush(XXH32_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the XXH64 multi-buffer manager structure.
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
void
xxh64_ctx_mgr_init(XXH64_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new XXH64 job to the multi-buffer manager.
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
XXH64_HASH_CTX *
xxh64_ctx_mgr_submit(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx, const void *buffer, uint32_t len,
                     HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted XXH64 jobs and return when complete.
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
XXH64_HASH_CTX *
xxh64_ctx_mgr_flush(XXH64_HASH_CTX_MGR *mgr);

#ifdef __cplusplus
}
#endif

#endif // _XXHASH_MB_H_
