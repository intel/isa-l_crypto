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

#ifndef _MH_SHA1_MURMUR3_X64_128_H_
#define _MH_SHA1_MURMUR3_X64_128_H_

/**
 *  @file mh_sha1_murmur3_x64_128.h
 *  @brief mh_sha1_murmur3_x64_128 function prototypes and structures
 *
 *  Interface for mh_sha1_murmur3_x64_128 functions
 *
 * <b> mh_sha1_murmur3_x64_128  Init-Update..Update-Finalize </b>
 *
 * This file defines the interface to optimized functions used in mh_sha1 and
 * mh_sha1_murmur3_x64_128.  The definition of multi-hash SHA1(mh_sha1,
 * for short) is: Pad the buffer in SHA1 style until the total length is a multiple
 * of 4*16*16(words-width * parallel-segments * block-size); Hash the buffer
 * in parallel, generating digests of 4*16*5 (words-width*parallel-segments*
 * digest-size); Treat the set of digests as another data buffer, and generate
 * a final SHA1 digest for it. mh_sha1_murmur3_x64_128 is a stitching function
 * which will get a murmur3_x64_128 digest while generate mh_sha1 digest.
 *
 *
 * Example
 * \code
 * uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS];
 * uint32_t murmur_digest[ISAL_MURMUR3_x64_128_DIGEST_WORDS];
 * struct isal_mh_sha1_murmur3_x64_128_ctx *ctx;
 *
 * ctx = malloc(sizeof(struct isal_mh_sha1_murmur3_x64_128_ctx));
 * isal_mh_sha1_murmur3_x64_128_init(ctx, 0);
 * isal_mh_sha1_murmur3_x64_128_update(ctx, buff, block_len);
 * isal_mh_sha1_murmur3_x64_128_finalize(ctx, mh_sha1_digest,
 * murmur_digest);
 * \endcode
 */

#include <stdint.h>
#include "mh_sha1.h"

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
// External Interface Definition
// Add murmur3_x64_128 definition

#define MUR_BLOCK_SIZE               ISAL_MUR_BLOCK_SIZE
#define MURMUR3_x64_128_DIGEST_WORDS ISAL_MURMUR3_x64_128_DIGEST_WORDS

#define MH_SHA1_MURMUR3_CTX_ERROR_NONE ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE
#define MH_SHA1_MURMUR3_CTX_ERROR_NULL ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NULL

#define mh_sha1_murmur3_x64_128_ctx isal_mh_sha1_murmur3_x64_128_ctx
#define mh_sha1_murmur3_ctx_error   isal_mh_sha1_murmur3_ctx_error
#endif /* NO_COMPAT_ISAL_CRYPTO_API_2_24 */

#define ISAL_MUR_BLOCK_SIZE               (2 * sizeof(uint64_t))
#define ISAL_MURMUR3_x64_128_DIGEST_WORDS 4

/** @brief Holds info describing a single mh_sha1_murmur3_x64_128
 *
 * It is better to use heap to allocate this data structure to avoid stack overflow.
 *
 */
struct isal_mh_sha1_murmur3_x64_128_ctx {
        uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]; //!< the digest of multi-hash SHA1
        uint32_t murmur3_x64_128_digest[ISAL_MURMUR3_x64_128_DIGEST_WORDS]; //!< the digest of
                                                                            //!< murmur3_x64_128

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
 *  @enum isal_mh_sha1_murmur3_ctx_error
 *  @brief CTX error flags
 */
enum isal_mh_sha1_murmur3_ctx_error {
        ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE = 0,  //!< ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NONE
        ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NULL = -1, //!< ISAL_MH_SHA1_MURMUR3_CTX_ERROR_NULL
};

/*******************************************************************
 * mh_sha1_murmur3_x64_128 API function prototypes
 ******************************************************************/

/**
 * @brief Initialize the isal_mh_sha1_murmur3_x64_128_ctx structure.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  murmur_seed Seed as an initial digest of murmur3
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_murmur3_x64_128_init() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_murmur3_x64_128_init() instead")
int
mh_sha1_murmur3_x64_128_init(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx, uint64_t murmur_seed);

/**
 * @brief Combined multi-hash and murmur hash update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_murmur3_x64_128_update() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_murmur3_x64_128_update() instead")
int
mh_sha1_murmur3_x64_128_update(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx, const void *buffer,
                               uint32_t len);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digests in mh_sha1_digest and murmur3_x64_128_digest,
 * which must have enough space for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  mh_sha1_digest The digest of mh_sha1
 * @param  murmur3_x64_128_digest The digest of murmur3_x64_128
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_murmur3_x64_128_finalize() instead.
 */
ISAL_DEPRECATED("Please use isal_mh_sha1_murmur3_x64_128_finalize() instead")
int
mh_sha1_murmur3_x64_128_finalize(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx, void *mh_sha1_digest,
                                 void *murmur3_x64_128_digest);

/*******************************************************************
 * multi-types of mh_sha1_murmur3_x64_128 internal API
 *
 * XXXX		The multi-binary version
 * XXXX_base	The C code version which used to display the algorithm
 * XXXX_sse	The version uses a ASM function optimized for SSE
 * XXXX_avx	The version uses a ASM function optimized for AVX
 * XXXX_avx2	The version uses a ASM function optimized for AVX2
 *
 ******************************************************************/

/**
 * @brief Combined multi-hash and murmur hash update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * Base update() function that does not require SIMD support.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_murmur3_x64_128_update() instead.
 */
int
mh_sha1_murmur3_x64_128_update_base(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx,
                                    const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digests in mh_sha1_digest and murmur3_x64_128_digest,
 * which must have enough space for the outputs.
 * Base Finalize() function that does not require SIMD support.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  mh_sha1_digest The digest of mh_sha1
 * @param  murmur3_x64_128_digest The digest of murmur3_x64_128
 * @returns int Return 0 if the function runs without errors
 * @deprecated Please use isal_mh_sha1_murmur3_x64_128_finalize() instead.
 */
int
mh_sha1_murmur3_x64_128_finalize_base(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx,
                                      void *mh_sha1_digest, void *murmur3_x64_128_digest);

/**
 * @brief Initialize the isal_mh_sha1_murmur3_x64_128_ctx structure.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  murmur_seed Seed as an initial digest of murmur3
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_murmur3_x64_128_init(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx,
                                  const uint64_t murmur_seed);

/**
 * @brief Combined multi-hash and murmur hash update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_murmur3_x64_128_update(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx,
                                    const void *buffer, const uint32_t len);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digests in mh_sha1_digest and murmur3_x64_128_digest,
 * which must have enough space for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha1_murmur3_x64_128 info
 * @param  mh_sha1_digest The digest of mh_sha1 (5*4 bytes)
 * @param  murmur3_x64_128_digest The digest of murmur3_x64_128 (4*4 bytes)
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_mh_sha1_murmur3_x64_128_finalize(struct isal_mh_sha1_murmur3_x64_128_ctx *ctx,
                                      void *mh_sha1_digest, void *murmur3_x64_128_digest);
#ifdef __cplusplus
}
#endif

#endif
