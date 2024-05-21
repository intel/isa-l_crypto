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

#ifndef _MH_SHA1_INTERNAL_H_
#define _MH_SHA1_INTERNAL_H_

/**
 *  @file mh_sha1_internal.h
 *  @brief mh_sha1 internal function prototypes and macros
 *
 *  Interface for mh_sha1 internal functions
 *
 */
#include <stdint.h>
#include "mh_sha1.h"
#include "endian_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#define inline __inline
#endif

// 64byte pointer align
#define ALIGN_64(pointer) (((uint64_t) (pointer) + 0x3F) & (~0x3F))

/*******************************************************************
 *mh_sha1 constants and macros
 ******************************************************************/
/* mh_sha1 constants */
#define MH_SHA1_H0 0x67452301UL
#define MH_SHA1_H1 0xefcdab89UL
#define MH_SHA1_H2 0x98badcfeUL
#define MH_SHA1_H3 0x10325476UL
#define MH_SHA1_H4 0xc3d2e1f0UL

#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

/* mh_sha1 macros */
#define F1(b, c, d) (d ^ (b & (c ^ d)))
#define F2(b, c, d) (b ^ c ^ d)
#define F3(b, c, d) ((b & c) | (d & (b | c)))
#define F4(b, c, d) (b ^ c ^ d)

#define rol32(x, r) (((x) << (r)) ^ ((x) >> (32 - (r))))

/**
 * @brief Initialize the isal_mh_sha1_ctx structure.
 *
 * @param  ctx Structure holding mh_sha1 info
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha1_init(struct isal_mh_sha1_ctx *ctx);

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
 */
int
_mh_sha1_update(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

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
 */
int
_mh_sha1_finalize(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/*******************************************************************
 * multi-types of mh_sha1 internal API
 *
 * XXXX		The multi-binary version
 * XXXX_base	The C code version which used to display the algorithm
 * XXXX_sse	The version uses a ASM function optimized for SSE
 * XXXX_avx	The version uses a ASM function optimized for AVX
 * XXXX_avx2	The version uses a ASM function optimized for AVX2
 * XXXX_avx512	The version uses a ASM function optimized for AVX512
 *
 ******************************************************************/

/**
 * @brief Multi-hash sha1 update base implementation.
 *
 * Can be called repeatedly to update hashes with new input data.
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha1_update_base(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_update_sse(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_update_avx(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_update_avx2(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha1 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_update_avx512(struct isal_mh_sha1_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha1_finalize_base(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 *
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_finalize_sse(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_finalize_avx(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_finalize_avx2(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha1_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha1 info
 * @param   mh_sha1_digest The digest of mh_sha1
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha1_finalize_avx512(struct isal_mh_sha1_ctx *ctx, void *mh_sha1_digest);
/*******************************************************************
 * SHA1 API internal function prototypes
 ******************************************************************/

/**
 * @brief Performs complete SHA1 algorithm.
 *
 * @param input  Pointer to buffer containing the input message.
 * @param digest Pointer to digest to update.
 * @param len	  Length of buffer.
 * @returns None
 */
void
_sha1_for_mh_sha1(const uint8_t *input_data, uint32_t *digest, const uint32_t len);

/*******************************************************************
 * mh_sha1 API internal function prototypes
 * Multiple versions of Update and Finalize functions are supplied which use
 * multiple versions of block and tail process subfunctions.
 ******************************************************************/

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @returns none
 *
 */
void
_mh_sha1_tail(uint8_t *partial_buffer, uint32_t total_len,
              uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
              uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha1_digest mh_sha1 digest
 * @returns none
 *
 */
void
_mh_sha1_tail_base(uint8_t *partial_buffer, uint32_t total_len,
                   uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                   uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * @requires SSE
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha1_digest mh_sha1 digest
 * @returns none
 *
 */
void
_mh_sha1_tail_sse(uint8_t *partial_buffer, uint32_t total_len,
                  uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                  uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * @requires AVX
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha1_digest mh_sha1 digest
 * @returns none
 *
 */
void
_mh_sha1_tail_avx(uint8_t *partial_buffer, uint32_t total_len,
                  uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                  uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * @requires AVX2
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha1_digest mh_sha1 digest
 * @returns none
 *
 */
void
_mh_sha1_tail_avx2(uint8_t *partial_buffer, uint32_t total_len,
                   uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                   uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha1.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA1_BLOCK_SIZE.
 * It will output the final SHA1 digest based on mh_sha1_segs_digests.
 *
 * @requires AVX512
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha1_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha1_digest mh_sha1 digest
 * @returns none
 *
 */
void
_mh_sha1_tail_avx512(uint8_t *partial_buffer, uint32_t total_len,
                     uint32_t (*mh_sha1_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                     uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block(const uint8_t *input_data, uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
               uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block_base(const uint8_t *input_data,
                    uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                    uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * @requires SSE
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block_sse(const uint8_t *input_data,
                   uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                   uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * @requires AVX
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block_avx(const uint8_t *input_data,
                   uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                   uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * @requires AVX2
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block_avx2(const uint8_t *input_data,
                    uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                    uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha1 digest of blocks which size is ISAL_MH_SHA1_BLOCK_SIZE*N.
 *
 * @requires AVX512
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha1_block_avx512(const uint8_t *input_data,
                      uint32_t digests[ISAL_SHA1_DIGEST_WORDS][ISAL_HASH_SEGS],
                      uint8_t frame_buffer[ISAL_MH_SHA1_BLOCK_SIZE], uint32_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif
