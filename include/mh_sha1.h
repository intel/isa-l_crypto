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

#ifndef _MH_SHA1_H_
#define _MH_SHA1_H_

/**
 *  @file mh_sha1.h
 *  @brief mh_sha1 function prototypes and structures
 *
 *  Interface for mh_sha1 functions
 *
 * <b> mh_sha1  Init-Update..Update-Finalize </b>
 *
 * This file defines the interface to optimized functions used in mh_sha1.
 * The definition of multi-hash SHA1(mh_sha1, for short) is: Pad the buffer
 * in SHA1 style until the total length is a multiple of 4*16*16
 * (words-width * parallel-segments * block-size); Hash the buffer in
 * parallel, generating digests of 4*16*5 (words-width*parallel-segments*
 * digest-size); Treat the set of digests as another data buffer, and
 * generate a final SHA1 digest for it.
 *
 *
 * Example
 * \code
 * uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS];
 * struct isal_mh_sha1_ctx *ctx;
 *
 * ctx = malloc(sizeof(struct isal_mh_sha1_ctx));
 * isal_mh_sha1_init(ctx);
 * isal_mh_sha1_update(ctx, buff, block_len);
 * isal_mh_sha1_finalize(ctx, mh_sha1_digest);
 * \endcode
 */

#include <stdint.h>
#include "types.h"

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
#define HASH_SEGS          ISAL_HASH_SEGS
#define SHA1_BLOCK_SIZE    ISAL_SHA1_BLOCK_SIZE
#define MH_SHA1_BLOCK_SIZE ISAL_MH_SHA1_BLOCK_SIZE
#define SHA1_DIGEST_WORDS  ISAL_SHA1_DIGEST_WORDS
#define AVX512_ALIGNED     ISAL_AVX512_ALIGNED

#define MH_SHA1_CTX_ERROR_NONE ISAL_MH_SHA1_CTX_ERROR_NONE
#define MH_SHA1_CTX_ERROR_NULL ISAL_MH_SHA1_CTX_ERROR_NULL

#define mh_sha1_ctx isal_mh_sha1_ctx
#endif /* !NO_COMPAT_ISAL_CRYPTO_API_2_24 */

// External Interface Definition
#define ISAL_HASH_SEGS          16
#define ISAL_SHA1_BLOCK_SIZE    64
#define ISAL_MH_SHA1_BLOCK_SIZE (ISAL_HASH_SEGS * ISAL_SHA1_BLOCK_SIZE)
#define ISAL_SHA1_DIGEST_WORDS  5
#define ISAL_AVX512_ALIGNED     64

/** @brief Holds info describing a single mh_sha1
 *
 * It is better to use heap to allocate this data structure to avoid stack overflow.
 *
 */
struct isal_mh_sha1_ctx {
        uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]; //!< the digest of multi-hash SHA1

        uint64_t total_length;
        //!<  Parameters for update feature, describe the lengths of input buffers in bytes
        uint8_t partial_block_buffer[ISAL_MH_SHA1_BLOCK_SIZE * 2];
        //!<  Padding the tail of input data for SHA1
        uint8_t mh_sha1_interim_digests[sizeof(uint32_t) * ISAL_SHA1_DIGEST_WORDS * ISAL_HASH_SEGS];
        //!<  Storing the SHA1 interim digests of  all 16 segments. Each time, it will be copied to
        //!<  stack for 64-byte alignment purpose.
        uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE + ISAL_AVX512_ALIGNED];
        //!<  Re-structure sha1 block data from different segments to fit big endian. Use
        //!<  ISAL_AVX512_ALIGNED for 64-byte alignment purpose.
};

/**
 *  @enum isal_mh_sha1_ctx_error
 *  @brief CTX error flags
 */
enum isal_mh_sha1_ctx_error {
        ISAL_MH_SHA1_CTX_ERROR_NONE = 0,  //!< ISAL_MH_SHA1_CTX_ERROR_NONE
        ISAL_MH_SHA1_CTX_ERROR_NULL = -1, //!< ISAL_MH_SHA1_CTX_ERROR_NULL
};

/*******************************************************************
 * mh_sha1 API function prototypes
 ******************************************************************/

/**
 * @brief Initialize the isal_mh_sha1_ctx structure.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_init() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_init() instead")
int
mh_sha1_init(struct isal_mh_sha1_ctx *ctx);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_update() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_update() instead")
int
mh_sha1_update(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for multi-hash sha1.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_finalize() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_finalize() instead")
int
mh_sha1_finalize(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * Base update() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_update() instead.
 */
int
mh_sha1_update_base(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for multi-hash sha1.
 *
 * Place the message digests in mh_sha1_digest,
 * which must have enough space for the outputs.
 * Base Finalize() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_finalize() instead.
 */
int
mh_sha1_finalize_base(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Initialize the isal_mh_sha1_ctx structure.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_init(struct isal_mh_sha1_ctx *ctx);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_update(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for multi-hash sha1.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @param  mh_sha1_digest The digest of mh_sha1
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_finalize(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

#ifdef __cplusplus
}
#endif

#endif
