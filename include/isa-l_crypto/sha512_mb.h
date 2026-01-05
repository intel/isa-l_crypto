/**********************************************************************
  Copyright(c) 2011-2016 Intel Corporation All rights reserved.

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

#ifndef _SHA512_MB_H_
#define _SHA512_MB_H_

/**
 *  @file sha512_mb.h
 *  @brief Single/Multi-buffer CTX API SHA512 function prototypes and structures
 *
 * Interface for single and multi-buffer SHA512 functions
 *
 * <b> Single/Multi-buffer SHA512  Entire or First-Update..Update-Last </b>
 *
 * The interface to this single/multi-buffer hashing code is carried out through the
 * context-level (CTX) init, submit and flush functions and the ISAL_SHA512_HASH_CTX_MGR and
 * ISAL_SHA512_HASH_CTX objects. Numerous ISAL_SHA512_HASH_CTX objects may be instantiated by the
 * application for use with a single ISAL_SHA512_HASH_CTX_MGR.
 *
 * The CTX interface functions carry out the initialization and padding of the jobs
 * entered by the user and add them to the multi-buffer manager. The lower level "scheduler"
 * layer then processes the jobs in an out-of-order manner. The scheduler layer functions
 * are internal and are not intended to be invoked directly. Jobs can be submitted
 * to a CTX as a complete buffer to be hashed, using the ISAL_HASH_ENTIRE flag, or as partial
 * jobs which can be started using the ISAL_HASH_FIRST flag, and later resumed or finished
 * using the ISAL_HASH_UPDATE and ISAL_HASH_LAST flags respectively.
 *
 * <b>Note:</b> The submit function does not require data buffers to be block sized.
 *
 * The SHA512 CTX interface functions are available for 5 architectures: multi-buffer SSE,
 * AVX, AVX2, AVX512 and single-buffer SSE4 (which is used in the same way as the
 * multi-buffer code). In addition, a multibinary interface is provided, which selects the
 * appropriate architecture-specific function at runtime. This multibinary interface
 * selects the single buffer SSE4 functions when the platform is detected to be Silvermont.
 *
 * <b>Usage:</b> The application creates a ISAL_SHA512_HASH_CTX_MGR object and initializes it
 * with a call to sha512_ctx_mgr_init*() function, where henceforth "*" stands for the
 * relevant suffix for each architecture; _sse, _avx, _avx2, _avx512(or no suffix for the
 * multibinary version). The ISAL_SHA512_HASH_CTX_MGR object will be used to schedule processor
 * resources, with up to 2 ISAL_SHA512_HASH_CTX objects (or 4 in the AVX2 case, 8 in the AVX512
 * case) being processed at a time.
 *
 * Each ISAL_SHA512_HASH_CTX must be initialized before first use by the isal_hash_ctx_init macro
 * defined in multi_buffer.h. After initialization, the application may begin computing
 * a hash by giving the ISAL_SHA512_HASH_CTX to a ISAL_SHA512_HASH_CTX_MGR using the submit
 * functions sha512_ctx_mgr_submit*() with the ISAL_HASH_FIRST flag set. When the
 * ISAL_SHA512_HASH_CTX is returned to the application (via this or a later call to
 * sha512_ctx_mgr_submit*() or sha512_ctx_mgr_flush*()), the application can then re-submit it with
 * another call to sha512_ctx_mgr_submit*(), but without the ISAL_HASH_FIRST flag set.
 *
 * Ideally, on the last buffer for that hash, sha512_ctx_mgr_submit is called with
 * ISAL_HASH_LAST, although it is also possible to submit the hash with ISAL_HASH_LAST and a zero
 * length if necessary. When a ISAL_SHA512_HASH_CTX is returned after having been submitted with
 * ISAL_HASH_LAST, it will contain a valid hash. The ISAL_SHA512_HASH_CTX can be reused immediately
 * by submitting with ISAL_HASH_FIRST.
 *
 * For example, you would submit hashes with the following flags for the following numbers
 * of buffers:
 * <ul>
 *  <li> one buffer: ISAL_HASH_FIRST | ISAL_HASH_LAST  (or, equivalently, ISAL_HASH_ENTIRE)
 *  <li> two buffers: ISAL_HASH_FIRST, ISAL_HASH_LAST
 *  <li> three buffers: ISAL_HASH_FIRST, ISAL_HASH_UPDATE, ISAL_HASH_LAST
 * etc.
 * </ul>
 *
 * The order in which SHA512_CTX objects are returned is in general different from the order
 * in which they are submitted.
 *
 * A few possible error conditions exist:
 * <ul>
 *  <li> Submitting flags other than the allowed entire/first/update/last values
 *  <li> Submitting a context that is currently being managed by a ISAL_SHA512_HASH_CTX_MGR. (Note:
 *   This error case is not applicable to the single buffer SSE4 version)
 *  <li> Submitting a context after ISAL_HASH_LAST is used but before ISAL_HASH_FIRST is set.
 * </ul>
 *
 *  These error conditions are reported by returning the ISAL_SHA512_HASH_CTX immediately after
 *  a submit with its error member set to a non-zero error code (defined in
 *  multi_buffer.h). No changes are made to the ISAL_SHA512_HASH_CTX_MGR in the case of an
 *  error; no processing is done for other hashes.
 *
 */

#include <stdint.h>
#include <string.h>
#include "multi_buffer.h"
#include "types.h"

#ifndef _MSC_VER
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define enums from API v2.24, so applications that were using this version
 * will still be compiled successfully.
 * This list does not need to be extended for new definitions.
 */
#ifndef NO_COMPAT_ISAL_CRYPTO_API_2_24
/***** Previous hash constants and typedefs *****/
#define SHA512_DIGEST_NWORDS       ISAL_SHA512_DIGEST_NWORDS
#define SHA512_PADLENGTHFIELD_SIZE ISAL_SHA512_PADLENGTHFIELD_SIZE
#define SHA512_MAX_LANES           ISAL_SHA512_MAX_LANES
#define SHA512_MIN_LANES           ISAL_SHA512_MIN_LANES
#define SHA512_BLOCK_SIZE          ISAL_SHA512_BLOCK_SIZE
#define SHA512_WORD_T              ISAL_SHA512_WORD_T

/***** Previous structure definitions *****/
#define SHA512_JOB          ISAL_SHA512_JOB
#define SHA512_MB_ARGS_X8   ISAL_SHA512_MB_ARGS_X8
#define SHA512_LANE_DATA    ISAL_SHA512_LANE_DATA
#define SHA512_MB_JOB_MGR   ISAL_SHA512_MB_JOB_MGR
#define SHA512_HASH_CTX_MGR ISAL_SHA512_HASH_CTX_MGR
#define SHA512_HASH_CTX     ISAL_SHA512_HASH_CTX
#endif /* !NO_COMPAT_ISAL_CRYPTO_API_2_24 */

// Hash Constants and Typedefs
#define ISAL_SHA512_DIGEST_NWORDS       8
#define ISAL_SHA512_MAX_LANES           8
#define ISAL_SHA512_MIN_LANES           2
#define ISAL_SHA512_BLOCK_SIZE          128
#define ISAL_SHA512_PADLENGTHFIELD_SIZE 16

typedef uint64_t sha512_digest_array[ISAL_SHA512_DIGEST_NWORDS][ISAL_SHA512_MAX_LANES];
typedef uint64_t ISAL_SHA512_WORD_T;

/** @brief Scheduler layer - Holds info describing a single SHA512 job for the multi-buffer manager
 */

typedef struct {
        uint8_t *buffer; //!< pointer to data buffer for this job
        uint64_t len;    //!< length of buffer for this job in blocks.
        DECLARE_ALIGNED(uint64_t result_digest[ISAL_SHA512_DIGEST_NWORDS], 64);
        ISAL_JOB_STS status; //!< output job status
        void *user_data;     //!< pointer for user's job-related data
} ISAL_SHA512_JOB;

/** @brief Scheduler layer -  Holds arguments for submitted SHA512 job */

typedef struct {
        sha512_digest_array digest;
        uint8_t *data_ptr[ISAL_SHA512_MAX_LANES];
} ISAL_SHA512_MB_ARGS_X8;

/** @brief Scheduler layer - Lane data */

typedef struct {
        ISAL_SHA512_JOB *job_in_lane;
} ISAL_SHA512_LANE_DATA;

/** @brief Scheduler layer - Holds state for multi-buffer SHA512 jobs */

typedef struct {
        ISAL_SHA512_MB_ARGS_X8 args;
        uint64_t lens[ISAL_SHA512_MAX_LANES];
        uint64_t unused_lanes; //!< each byte is index (00, 01 or 00...03) of unused lanes, byte 2
                               //!< or 4 is set to FF as a flag
        ISAL_SHA512_LANE_DATA ldata[ISAL_SHA512_MAX_LANES];
        uint32_t num_lanes_inuse;
} ISAL_SHA512_MB_JOB_MGR;

/** @brief Context layer - Holds state for multi-buffer SHA512 jobs */

typedef struct {
        ISAL_SHA512_MB_JOB_MGR mgr;
} ISAL_SHA512_HASH_CTX_MGR;

/** @brief Context layer - Holds info describing a single SHA512 job for the multi-buffer CTX
 * manager */

typedef struct {
        ISAL_SHA512_JOB job;             // Must be at struct offset 0.
        ISAL_HASH_CTX_STS status;        //!< Context status flag
        ISAL_HASH_CTX_ERROR error;       //!< Context error flag
        uint64_t total_length;           //!< Running counter of length processed for this CTX's job
        const void *incoming_buffer;     //!< pointer to data input buffer for this CTX's job
        uint32_t incoming_buffer_length; //!< length of buffer for this job in bytes.
        uint8_t partial_block_buffer[ISAL_SHA512_BLOCK_SIZE * 2]; //!< CTX partial blocks
        uint32_t partial_block_buffer_length;
        void *user_data; //!< pointer for user to keep any job-related data
} ISAL_SHA512_HASH_CTX;

/******************** multibinary function prototypes **********************/

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires SSE4.1 or AVX or AVX2 or AVX512
 * @deprecated Please use isal_sha512_ctx_mgr_init() instead.
 *
 * @param mgr	Structure holding context level state info
 * @returns void
 */
ISAL_DEPRECATED("Please use isal_sha512_ctx_mgr_init() instead")
void
sha512_ctx_mgr_init(ISAL_SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires SSE4.1 or AVX or AVX2 or AVX512
 * @deprecated Please use isal_sha512_ctx_mgr_submit() instead.
 *
 * @param  mgr Structure holding context level state info
 * @param  ctx Structure holding ctx job info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @param  flags Input flag specifying job type (first, update, last or entire)
 * @returns NULL if no jobs complete or pointer to jobs structure.
 */
ISAL_DEPRECATED("Please use isal_sha512_ctx_mgr_submit() instead")
ISAL_SHA512_HASH_CTX *
sha512_ctx_mgr_submit(ISAL_SHA512_HASH_CTX_MGR *mgr, ISAL_SHA512_HASH_CTX *ctx, const void *buffer,
                      uint32_t len, ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires SSE4.1 or AVX or AVX2 or AVX512
 * @deprecated Please use isal_sha512_ctx_mgr_flush() instead.
 *
 * @param mgr	Structure holding context level state info
 * @returns NULL if no jobs to complete or pointer to jobs structure.
 */
ISAL_DEPRECATED("Please use isal_sha512_ctx_mgr_flush() instead")
ISAL_SHA512_HASH_CTX *
sha512_ctx_mgr_flush(ISAL_SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief Initialize the SHA512 multi-buffer manager structure.
 * @requires SSE4.1 for x86 or ASIMD for ARM
 *
 * @param[in] mgr Structure holding context level state info
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_sha512_ctx_mgr_init(ISAL_SHA512_HASH_CTX_MGR *mgr);

/**
 * @brief  Submit a new SHA512 job to the multi-buffer manager.
 * @requires SSE4.1 for x86 or ASIMD for ARM
 *
 * @param[in] mgr Structure holding context level state info
 * @param[in] ctx_in Structure holding ctx job info
 * @param[out] ctx_out	Pointer address to output job ctx info.
 *			Modified to point to completed job structure or
 *			NULL if no jobs completed.
 * @param[in] buffer Pointer to buffer to be processed
 * @param[in] len Length of buffer (in bytes) to be processed
 * @param[in] flags Input flag specifying job type (first, update, last or entire)
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_sha512_ctx_mgr_submit(ISAL_SHA512_HASH_CTX_MGR *mgr, ISAL_SHA512_HASH_CTX *ctx_in,
                           ISAL_SHA512_HASH_CTX **ctx_out, const void *buffer, const uint32_t len,
                           const ISAL_HASH_CTX_FLAG flags);

/**
 * @brief Finish all submitted SHA512 jobs and return when complete.
 * @requires SSE4.1 for x86 or ASIMD for ARM
 *
 * @param[in] mgr Structure holding context level state info
 * @param[out] ctx_out	Pointer address to output job ctx info.
 *			Modified to point to completed job structure or
 *			NULL if no jobs completed.
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_sha512_ctx_mgr_flush(ISAL_SHA512_HASH_CTX_MGR *mgr, ISAL_SHA512_HASH_CTX **ctx_out);
#ifdef __cplusplus
}
#endif

#endif // _SHA512_MB_H_
