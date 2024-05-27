/**********************************************************************
  Copyright(c) 2011-2024 Intel Corporation All rights reserved.

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

#include "types.h"

/**
 *  @file aes_gcm.h
 *  @brief AES GCM encryption/decryption function prototypes.
 *
 * At build time there is an option to use non-temporal loads and stores
 * selected by defining the compile time option NT_LDST. The use of this option
 * places the following restriction on the gcm encryption functions:
 *
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 *
 * - When using the streaming API, all partial input buffers must be a multiple
 *   of 64 bytes long except for the last input buffer.
 *
 * - In-place encryption/decryption is not recommended.
 *
 */

/*
; References:
;       This code was derived and highly optimized from the code described in paper:
;               Vinodh Gopal et. al. Optimized Galois-Counter-Mode Implementation on Intel
Architecture Processors. August, 2010
;
;       For the shift-based reductions used in this code, we used the method described in paper:
;               Shay Gueron, Michael E. Kounavis. Intel Carry-Less Multiplication Instruction and
its Usage for Computing the GCM Mode. January, 2010.
;
;
;
; Assumptions: Support for SSE4.1 or greater, AVX or AVX2
;
;
; iv:
;       0                   1                   2                   3
;       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                             Salt  (From the SA)               |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                     Initialization Vector                     |
;       |         (This is the sequence number from IPSec header)       |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;       |                              0x1                              |
;       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;
; TLen:
;       from the definition of the spec, TLen can only be 8, 12 or 16 bytes.
;
 */
#ifndef _AES_GCM_h
#define _AES_GCM_h

#include <stdint.h>

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
#define MAX_TAG_LEN ISAL_GCM_MAX_TAG_LEN

#define GCM_IV_LEN       (16)
#define GCM_IV_DATA_LEN  ISAL_GCM_IV_LEN
#define GCM_IV_END_MARK  { 0x00, 0x00, 0x00, 0x01 };
#define GCM_IV_END_START (12)

#define GCM_128_KEY_LEN ISAL_GCM_128_KEY_LEN
#define GCM_256_KEY_LEN ISAL_GCM_256_KEY_LEN

#define GCM_BLOCK_LEN   ISAL_GCM_BLOCK_LEN
#define GCM_ENC_KEY_LEN ISAL_GCM_ENC_KEY_LEN
#define GCM_KEY_SETS    ISAL_GCM_KEY_SETS

#define GCM_MAX_LEN ISAL_GCM_MAX_LEN

#define LONGEST_TESTED_AAD_LENGTH (2 * 1024)

#define gcm_key_data     isal_gcm_key_data
#define gcm_context_data isal_gcm_context_data
#endif /* !NO_COMPAT_ISAL_CRYPTO_API_2_24 */

/* Authenticated Tag Length in bytes. Valid values are 16 (most likely), 12 or 8. */
#define ISAL_GCM_MAX_TAG_LEN (16)
//
// IV data is limited to 12 bytes.
//
#define ISAL_GCM_IV_LEN (12)

// Key lengths of 128 and 256 supported
#define ISAL_GCM_128_KEY_LEN (16)
#define ISAL_GCM_256_KEY_LEN (32)

#define ISAL_GCM_BLOCK_LEN   16
#define ISAL_GCM_ENC_KEY_LEN 16
#define ISAL_GCM_KEY_SETS    (15) /*exp key + 14 exp round keys */

#define ISAL_GCM_MAX_LEN UINT64_C(((1ULL << 39) - 256) - 1)

/**
 * @brief holds intermediate key data needed to improve performance
 *
 * isal_gcm_key_data hold internal key information used by gcm128 and gcm256.
 */
#ifdef __WIN32
__declspec(align(16))
#endif /* WIN32 */
struct isal_gcm_key_data {
        uint8_t expanded_keys[ISAL_GCM_ENC_KEY_LEN * ISAL_GCM_KEY_SETS];
        uint8_t shifted_hkey_1[ISAL_GCM_ENC_KEY_LEN];   // store HashKey <<1 mod poly here
        uint8_t shifted_hkey_2[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^2 <<1 mod poly here
        uint8_t shifted_hkey_3[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^3 <<1 mod poly here
        uint8_t shifted_hkey_4[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^4 <<1 mod poly here
        uint8_t shifted_hkey_5[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^5 <<1 mod poly here
        uint8_t shifted_hkey_6[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^6 <<1 mod poly here
        uint8_t shifted_hkey_7[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^7 <<1 mod poly here
        uint8_t shifted_hkey_8[ISAL_GCM_ENC_KEY_LEN];   // store HashKey^8 <<1 mod poly here
        uint8_t shifted_hkey_1_k[ISAL_GCM_ENC_KEY_LEN]; // store XOR of High 64 bits
        uint8_t shifted_hkey_2_k[ISAL_GCM_ENC_KEY_LEN]; // and Low 64b of HashKey^n <<1 mod poly
        uint8_t shifted_hkey_3_k[ISAL_GCM_ENC_KEY_LEN]; // here (for Karatsuba purposes)
        uint8_t shifted_hkey_4_k[ISAL_GCM_ENC_KEY_LEN];
        uint8_t shifted_hkey_5_k[ISAL_GCM_ENC_KEY_LEN];
        uint8_t shifted_hkey_6_k[ISAL_GCM_ENC_KEY_LEN];
        uint8_t shifted_hkey_7_k[ISAL_GCM_ENC_KEY_LEN];
        uint8_t shifted_hkey_8_k[ISAL_GCM_ENC_KEY_LEN];
        uint8_t shifted_hkey_n_k[ISAL_GCM_ENC_KEY_LEN *
                                 (64 - 16)]; // Others vaes version needs 2x32
}
#if defined(__unix__) || (__MINGW32__)
__attribute__((aligned(16)));
#else
;
#endif

/**
 * @brief holds GCM operation context
 */
struct isal_gcm_context_data {
        // init, update and finalize context data
        uint8_t aad_hash[ISAL_GCM_BLOCK_LEN];
        uint64_t aad_length;
        uint64_t in_length;
        uint8_t partial_block_enc_key[ISAL_GCM_BLOCK_LEN];
        uint8_t orig_IV[ISAL_GCM_BLOCK_LEN];
        uint8_t current_counter[ISAL_GCM_BLOCK_LEN];
        uint64_t partial_block_length;
};

/* ------------------ New interface for separate expanded keys ------------ */

/**
 * @brief GCM-AES Encryption using 128 bit keys
 *
 * @deprecated Please use isal_aes_gcm_enc_128() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_128() instead.")
void
aes_gcm_enc_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                struct isal_gcm_context_data *context_data, //!< GCM operation context data
                uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed
                uint8_t const *in, //!< Plaintext input
                uint64_t len,      //!< Length of data in Bytes for encryption
                uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                //!< Internally, library concates 0x00000001 value to it.
                uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                uint64_t aad_len,     //!< Length of AAD
                uint8_t *auth_tag,    //!< Authenticated Tag output
                uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                      //!< 4 bytes).
                                      //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Encryption using 256 bit keys
 *
 * @deprecated Please use isal_aes_gcm_enc_256() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_256() instead.")
void
aes_gcm_enc_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                struct isal_gcm_context_data *context_data, //!< GCM operation context data
                uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed
                uint8_t const *in, //!< Plaintext input
                uint64_t len,      //!< Length of data in Bytes for encryption
                uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                //!< Internally, library concates 0x00000001 value to it.
                uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                uint64_t aad_len,     //!< Length of AAD
                uint8_t *auth_tag,    //!< Authenticated Tag output
                uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                      //!< 4 bytes).
                                      //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 *
 * @deprecated Please use isal_aes_gcm_dec_128() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_128() instead.")
void
aes_gcm_dec_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                struct isal_gcm_context_data *context_data, //!< GCM operation context data
                uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed
                uint8_t const *in, //!< Ciphertext input
                uint64_t len,      //!< Length of data in Bytes for decryption
                uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                //!< Internally, library concates 0x00000001 value to it.
                uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                uint64_t aad_len,     //!< Length of AAD
                uint8_t *auth_tag,    //!< Authenticated Tag output
                uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                      //!< 4 bytes).
                                      //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 *
 * @deprecated Please use isal_aes_gcm_dec_256() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_256() instead.")
void
aes_gcm_dec_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                struct isal_gcm_context_data *context_data, //!< GCM operation context data
                uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed
                uint8_t const *in, //!< Ciphertext input
                uint64_t len,      //!< Length of data in Bytes for decryption
                uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                //!< Internally, library concates 0x00000001 value to it.
                uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                uint64_t aad_len,     //!< Length of AAD
                uint8_t *auth_tag,    //!< Authenticated Tag output
                uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                      //!< 4 bytes).
                                      //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Start a AES-GCM Encryption message 128 bit key
 *
 * @deprecated Please use isal_aes_gcm_init_128() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_init_128() instead.")
void
aes_gcm_init_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                 struct isal_gcm_context_data *context_data, //!< GCM operation context data
                 uint8_t *iv,                                //!< Pointer to 12 byte IV structure
                 //!< Internally, library concates 0x00000001 value to it
                 uint8_t const *aad, //!< Additional Authentication Data (AAD)
                 uint64_t aad_len    //!< Length of AAD
);

/**
 * @brief Start a AES-GCM Encryption message 256 bit key
 *
 * @deprecated Please use isal_aes_gcm_init_256() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_init_256() instead.")
void
aes_gcm_init_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                 struct isal_gcm_context_data *context_data, //!< GCM operation context data
                 uint8_t *iv,                                //!< Pointer to 12 byte IV structure
                 //!< Internally, library concates 0x00000001 value to it
                 uint8_t const *aad, //!< Additional Authentication Data (AAD)
                 uint64_t aad_len    //!< Length of AAD
);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_enc_128_update() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_128_update() instead.")
void
aes_gcm_enc_128_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                       struct isal_gcm_context_data *context_data, //!< GCM operation context data
                       uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
                       const uint8_t *in, //!< Plaintext input
                       uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_enc_256_update() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_256_update() instead.")
void
aes_gcm_enc_256_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                       struct isal_gcm_context_data *context_data, //!< GCM operation context data
                       uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
                       const uint8_t *in, //!< Plaintext input
                       uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_dec_128_update() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_128_update() instead.")
void
aes_gcm_dec_128_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                       struct isal_gcm_context_data *context_data, //!< GCM operation context data
                       uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
                       const uint8_t *in, //!< Ciphertext input
                       uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_dec_256_update() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_256_update() instead.")
void
aes_gcm_dec_256_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                       struct isal_gcm_context_data *context_data, //!< GCM operation context data
                       uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
                       const uint8_t *in, //!< Ciphertext input
                       uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief End encryption of a AES-128-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_enc_128_finalize() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_128_finalize() instead.")
void
aes_gcm_enc_128_finalize(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                         struct isal_gcm_context_data *context_data, //!< GCM operation context data
                         uint8_t *auth_tag,                          //!< Authenticated Tag output
                         uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                               //!< multiple of 4 bytes).
                                               //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End encryption of a AES-256-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_enc_256_finalize() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_256_finalize() instead.")
void
aes_gcm_enc_256_finalize(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                         struct isal_gcm_context_data *context_data, //!< GCM operation context data
                         uint8_t *auth_tag,                          //!< Authenticated Tag output
                         uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                               //!< multiple of 4 bytes).
                                               //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-128-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_dec_128_finalize() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_128_finalize() instead.")
void
aes_gcm_dec_128_finalize(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                         struct isal_gcm_context_data *context_data, //!< GCM operation context data
                         uint8_t *auth_tag,                          //!< Authenticated Tag output
                         uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                               //!< multiple of 4 bytes).
                                               //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-256-GCM Encryption message
 *
 * @deprecated Please use isal_aes_gcm_dec_256_finalize() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_256_finalize() instead.")
void
aes_gcm_dec_256_finalize(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                         struct isal_gcm_context_data *context_data, //!< GCM operation context data
                         uint8_t *auth_tag,                          //!< Authenticated Tag output
                         uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                               //!< multiple of 4 bytes).
                                               //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @deprecated Please use isal_aes_gcm_pre_128() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_pre_128() instead.")
void
aes_gcm_pre_128(const void *key,                   //!< Pointer to key data
                struct isal_gcm_key_data *key_data //!< GCM expanded key data
);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @deprecated Please use isal_aes_gcm_pre_256() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_pre_256() instead.")
void
aes_gcm_pre_256(const void *key,                   //!< Pointer to key data
                struct isal_gcm_key_data *key_data //!< GCM expanded key data
);

/* ---- NT versions ---- */
/**
 * @brief GCM-AES Encryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_enc_128_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_128_nt() instead.")
void
aes_gcm_enc_128_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                   struct isal_gcm_context_data *context_data, //!< GCM operation context data
                   uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed
                   uint8_t const *in, //!< Plaintext input
                   uint64_t len,      //!< Length of data in Bytes for encryption
                   uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                   //!< Internally, library concates 0x00000001 value to it.
                   uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                   uint64_t aad_len,     //!< Length of AAD
                   uint8_t *auth_tag,    //!< Authenticated Tag output
                   uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                         //!< of 4 bytes).
                                         //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Encryption using 256 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_enc_256_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_256_nt() instead.")
void
aes_gcm_enc_256_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                   struct isal_gcm_context_data *context_data, //!< GCM operation context data
                   uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed
                   uint8_t const *in, //!< Plaintext input
                   uint64_t len,      //!< Length of data in Bytes for encryption
                   uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                   //!< Internally, library concates 0x00000001 value to it.
                   uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                   uint64_t aad_len,     //!< Length of AAD
                   uint8_t *auth_tag,    //!< Authenticated Tag output
                   uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                         //!< of 4 bytes).
                                         //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_dec_128_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_128_nt() instead.")
void
aes_gcm_dec_128_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                   struct isal_gcm_context_data *context_data, //!< GCM operation context data
                   uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed
                   uint8_t const *in, //!< Ciphertext input
                   uint64_t len,      //!< Length of data in Bytes for decryption
                   uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                   //!< Internally, library concates 0x00000001 value to it.
                   uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                   uint64_t aad_len,     //!< Length of AAD
                   uint8_t *auth_tag,    //!< Authenticated Tag output
                   uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                         //!< of 4 bytes).
                                         //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_dec_256_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_256_nt() instead.")
void
aes_gcm_dec_256_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                   struct isal_gcm_context_data *context_data, //!< GCM operation context data
                   uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed
                   uint8_t const *in, //!< Ciphertext input
                   uint64_t len,      //!< Length of data in Bytes for decryption
                   uint8_t *iv,       //!< iv pointer to 12 byte IV structure.
                   //!< Internally, library concates 0x00000001 value to it.
                   uint8_t const *aad,   //!< Additional Authentication Data (AAD)
                   uint64_t aad_len,     //!< Length of AAD
                   uint8_t *auth_tag,    //!< Authenticated Tag output
                   uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                         //!< of 4 bytes).
                                         //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_enc_128_update_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_128_update_nt() instead.")
void
aes_gcm_enc_128_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_enc_256_update_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_enc_256_update_nt() instead.")
void
aes_gcm_enc_256_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_dec_128_update_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_128_update_nt() instead.")
void
aes_gcm_dec_128_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @deprecated Please use isal_aes_gcm_dec_256_update_nt() instead.
 * @requires SSE4.1 and AESNI
 */
ISAL_DEPRECATED("Please use isal_aes_gcm_dec_256_update_nt() instead.")
void
aes_gcm_dec_256_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief GCM-AES Encryption using 128 bit keys
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_128(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Ciphertext output. Encrypt in-place is allowed
        const uint8_t *in,  //!< Plaintext input
        const uint64_t len, //!< Length of data in Bytes for encryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                    //!< 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Encryption using 256 bit keys
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_256(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Ciphertext output. Encrypt in-place is allowed
        const uint8_t *in,  //!< Plaintext input
        const uint64_t len, //!< Length of data in Bytes for encryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                    //!< 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_128(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Plaintext output. Decrypt in-place is allowed
        const uint8_t *in,  //!< Ciphertext input
        const uint64_t len, //!< Length of data in Bytes for decryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                    //!< 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_256(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Plaintext output. Decrypt in-place is allowed
        const uint8_t *in,  //!< Ciphertext input
        const uint64_t len, //!< Length of data in Bytes for decryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of
                                    //!< 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Start a AES-GCM Encryption message 128 bit key
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_init_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                      struct isal_gcm_context_data *context_data, //!< GCM operation context data
                      const uint8_t *iv, //!< Pointer to 12 byte IV structure
                      //!< Internally, library concates 0x00000001 value to it
                      const uint8_t *aad,    //!< Additional Authenticated Data (AAD)
                      const uint64_t aad_len //!< Length of AAD
);

/**
 * @brief Start a AES-GCM Encryption message 256 bit key
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_init_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                      struct isal_gcm_context_data *context_data, //!< GCM operation context data
                      const uint8_t *iv, //!< Pointer to 12 byte IV structure
                      //!< Internally, library concates 0x00000001 value to it
                      const uint8_t *aad,    //!< Additional Authenticated Data (AAD)
                      const uint64_t aad_len //!< Length of AAD
);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_128_update(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        const uint64_t len //!< Length of data in Bytes for encryption
);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_256_update(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        const uint64_t len //!< Length of data in Bytes for encryption
);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_128_update(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        const uint64_t len //!< Length of data in Bytes for decryption
);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_256_update(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        const uint64_t len //!< Length of data in Bytes for decryption
);

/**
 * @brief End encryption of a AES-128-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_128_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                    //!< multiple of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End encryption of a AES-256-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_256_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                    //!< multiple of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-128-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_128_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                    //!< multiple of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-256-GCM Encryption message
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_256_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                                    //!< multiple of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_pre_128(const void *key,                   //!< Pointer to key data
                     struct isal_gcm_key_data *key_data //!< GCM expanded key data
);

/**
 * @brief Pre-processes GCM key data 256 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_pre_256(const void *key,                   //!< Pointer to key data
                     struct isal_gcm_key_data *key_data //!< GCM expanded key data
);

/* ---- NT versions ---- */
/**
 * @brief GCM-AES Encryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_128_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Ciphertext output. Encrypt in-place is allowed
        const uint8_t *in,  //!< Plaintext input
        const uint64_t len, //!< Length of data in Bytes for encryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                    //!< of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Encryption using 256 bit keys, Non-temporal data
 *
 * Non-temporal version of encrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_256_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Ciphertext output. Encrypt in-place is allowed
        const uint8_t *in,  //!< Plaintext input
        const uint64_t len, //!< Length of data in Bytes for encryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                    //!< of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_128_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Plaintext output. Decrypt in-place is allowed
        const uint8_t *in,  //!< Ciphertext input
        const uint64_t len, //!< Length of data in Bytes for decryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                    //!< of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief GCM-AES Decryption using 128 bit keys, Non-temporal data
 *
 * Non-temporal version of decrypt has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_256_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,       //!< Plaintext output. Decrypt in-place is allowed
        const uint8_t *in,  //!< Ciphertext input
        const uint64_t len, //!< Length of data in Bytes for decryption
        const uint8_t *iv,  //!< iv pointer to 12 byte IV structure.
        //!< Internally, library concates 0x00000001 value to it.
        const uint8_t *aad,         //!< Additional Authenticated Data (AAD)
        const uint64_t aad_len,     //!< Length of AAD
        uint8_t *auth_tag,          //!< Authenticated Tag output
        const uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple
                                    //!< of 4 bytes).
                                    //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_128_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        const uint64_t len //!< Length of data in Bytes for encryption
);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of encrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_enc_256_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
        const uint8_t *in, //!< Plaintext input
        const uint64_t len //!< Length of data in Bytes for encryption
);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_128_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        const uint64_t len //!< Length of data in Bytes for decryption
);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message, Non-temporal data
 *
 * Non-temporal version of decrypt update has additional restrictions:
 * - The plaintext and ciphertext buffers must be aligned on a 64 byte boundary.
 * - All partial input buffers must be a multiple of 64 bytes long except for
 *   the last input buffer.
 * - In-place encryption/decryption is not recommended. Performance can be slow.
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_gcm_dec_256_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        const uint64_t len //!< Length of data in Bytes for decryption
);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _AES_GCM_h
