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

#ifndef _MH_SHA256_INTERNAL_H_
#define _MH_SHA256_INTERNAL_H_

/**
 *  @file mh_sha256_internal.h
 *  @brief mh_sha256 internal function prototypes and macros
 *
 *  Interface for mh_sha256 internal functions
 *
 */
#include <stdint.h>
#include "mh_sha256.h"
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
 *mh_sha256 constants and macros
 ******************************************************************/
/* mh_sha256 constants */
#define MH_SHA256_H0 0x6a09e667UL
#define MH_SHA256_H1 0xbb67ae85UL
#define MH_SHA256_H2 0x3c6ef372UL
#define MH_SHA256_H3 0xa54ff53aUL
#define MH_SHA256_H4 0x510e527fUL
#define MH_SHA256_H5 0x9b05688cUL
#define MH_SHA256_H6 0x1f83d9abUL
#define MH_SHA256_H7 0x5be0cd19UL

/* mh_sha256 macros */
#define ror32(x, r) (((x) >> (r)) ^ ((x) << (32 - (r))))

#define S0(w) (ror32(w, 7) ^ ror32(w, 18) ^ (w >> 3))
#define S1(w) (ror32(w, 17) ^ ror32(w, 19) ^ (w >> 10))

#define s0(a)        (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22))
#define s1(e)        (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25))
#define maj(a, b, c) ((a & b) ^ (a & c) ^ (b & c))
#define ch(e, f, g)  ((e & f) ^ (g & ~e))

/*******************************************************************
 * SHA256 API internal function prototypes
 ******************************************************************/

/**
 * @brief Initialize the isal_mh_sha256_ctx structure.
 *
 * @param  ctx Structure holding mh_sha256 info
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha256_init(struct isal_mh_sha256_ctx *ctx);

/**
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  ctx Structure holding mh_sha256 info
 * @param  buffer Pointer to buffer to be processed
 * @param  len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha256_update(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for multi-hash sha256.
 *
 * Place the message digest in mh_sha256_digest which must have enough space
 * for the outputs.
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 */
int
_mh_sha256_finalize(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/*******************************************************************
 * multi-types of mh_sha256 internal API
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
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * Base update() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_update_base(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for multi-hash sha256.
 *
 * Place the message digests in mh_sha256_digest,
 * which must have enough space for the outputs.
 * Base Finalize() function that does not require SIMD support.
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_finalize_base(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/**
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_update_sse(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_update_avx(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_update_avx2(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Multi-hash sha256 update.
 *
 * Can be called repeatedly to update hashes with new input data.
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   buffer Pointer to buffer to be processed
 * @param   len Length of buffer (in bytes) to be processed
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_update_avx512(struct isal_mh_sha256_ctx *ctx, const void *buffer, uint32_t len);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha256_digest which must have enough space
 * for the outputs.
 *
 * @requires SSE
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_finalize_sse(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha256_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_finalize_avx(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha256_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX2
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_finalize_avx2(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/**
 * @brief Finalize the message digests for combined multi-hash and murmur.
 *
 * Place the message digest in mh_sha256_digest which must have enough space
 * for the outputs.
 *
 * @requires AVX512
 *
 * @param   ctx Structure holding mh_sha256 info
 * @param   mh_sha256_digest The digest of mh_sha256
 * @returns int Return 0 if the function runs without errors
 *
 */
int
_mh_sha256_finalize_avx512(struct isal_mh_sha256_ctx *ctx, void *mh_sha256_digest);

/**
 * @brief Performs complete SHA256 algorithm.
 *
 * @param input  Pointer to buffer containing the input message.
 * @param digest Pointer to digest to update.
 * @param len	  Length of buffer.
 * @returns None
 */
void
sha256_for_mh_sha256(const uint8_t *input_data, uint32_t *digest, const uint32_t len);

/**
 * @brief Calculate sha256 digest of blocks which size is ISAL_SHA256_BLOCK_SIZE
 *
 * @param data   Pointer to data buffer containing the input message.
 * @param digest Pointer to sha256 digest.
 * @returns None
 */
void
sha256_single_for_mh_sha256(const uint8_t *data, uint32_t digest[]);

/*******************************************************************
 * mh_sha256 API internal function prototypes
 * Multiple versions of Update and Finalize functions are supplied which use
 * multiple versions of block and tail process subfunctions.
 ******************************************************************/

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * This function determines what instruction sets are enabled and selects the
 * appropriate version at runtime.
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @returns none
 *
 */
void
_mh_sha256_tail(uint8_t *partial_buffer, uint32_t total_len,
                uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha256_digest mh_sha256 digest
 * @returns none
 *
 */
void
_mh_sha256_tail_base(uint8_t *partial_buffer, uint32_t total_len,
                     uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                     uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * @requires SSE
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha256_digest mh_sha256 digest
 * @returns none
 *
 */
void
_mh_sha256_tail_sse(uint8_t *partial_buffer, uint32_t total_len,
                    uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                    uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * @requires AVX
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha256_digest mh_sha256 digest
 * @returns none
 *
 */
void
_mh_sha256_tail_avx(uint8_t *partial_buffer, uint32_t total_len,
                    uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                    uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * @requires AVX2
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha256_digest mh_sha256 digest
 * @returns none
 *
 */
void
_mh_sha256_tail_avx2(uint8_t *partial_buffer, uint32_t total_len,
                     uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                     uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Tail process for multi-hash sha256.
 *
 * Calculate the remainder of input data which is less than ISAL_MH_SHA256_BLOCK_SIZE.
 * It will output the final SHA256 digest based on mh_sha256_segs_digests.
 *
 * @requires AVX512
 *
 * @param  partial_buffer Pointer to the start addr of remainder
 * @param  total_len The total length of all sections of input data.
 * @param  mh_sha256_segs_digests The digests of all 16 segments .
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  mh_sha256_digest mh_sha256 digest
 * @returns none
 *
 */
void
_mh_sha256_tail_avx512(uint8_t *partial_buffer, uint32_t total_len,
                       uint32_t (*mh_sha256_segs_digests)[ISAL_HASH_SEGS], uint8_t *frame_buffer,
                       uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
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
_mh_sha256_block(const uint8_t *input_data,
                 uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                 uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
 *
 * @param  input_data Pointer to input data to be processed
 * @param  digests 16 segments digests
 * @param  frame_buffer Pointer to buffer which is a temp working area
 * @param  num_blocks The number of blocks.
 * @returns none
 *
 */
void
_mh_sha256_block_base(const uint8_t *input_data,
                      uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                      uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
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
_mh_sha256_block_sse(const uint8_t *input_data,
                     uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                     uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
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
_mh_sha256_block_avx(const uint8_t *input_data,
                     uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                     uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
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
_mh_sha256_block_avx2(const uint8_t *input_data,
                      uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                      uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

/**
 * @brief  Calculate mh_sha256 digest of blocks which size is ISAL_MH_SHA256_BLOCK_SIZE*N.
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
_mh_sha256_block_avx512(const uint8_t *input_data,
                        uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
                        uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif
