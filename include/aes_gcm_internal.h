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

/**
 * @file aes_gcm_internal.h
 * @brief AES GCM encryption/decryption internal function prototypes.
 *
 */

#ifndef _AES_GCM_INTERNAL_h
#define _AES_GCM_INTERNAL_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief GCM-AES Encryption using 128 bit keys
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_init_128(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                  struct isal_gcm_context_data *context_data, //!< GCM operation context data
                  uint8_t *iv,                                //!< Pointer to 12 byte IV structure
                  //!< Internally, library concates 0x00000001 value to it
                  uint8_t const *aad, //!< Additional Authentication Data (AAD)
                  uint64_t aad_len    //!< Length of AAD
);

/**
 * @brief Start a AES-GCM Encryption message 256 bit key
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_init_256(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                  struct isal_gcm_context_data *context_data, //!< GCM operation context data
                  uint8_t *iv,                                //!< Pointer to 12 byte IV structure
                  //!< Internally, library concates 0x00000001 value to it
                  uint8_t const *aad, //!< Additional Authentication Data (AAD)
                  uint64_t aad_len    //!< Length of AAD
);

/**
 * @brief Encrypt a block of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_128_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                        struct isal_gcm_context_data *context_data, //!< GCM operation context data
                        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
                        const uint8_t *in, //!< Plaintext input
                        uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Encrypt a block of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_256_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                        struct isal_gcm_context_data *context_data, //!< GCM operation context data
                        uint8_t *out,      //!< Ciphertext output. Encrypt in-place is allowed.
                        const uint8_t *in, //!< Plaintext input
                        uint64_t len       //!< Length of data in Bytes for encryption
);

/**
 * @brief Decrypt a block of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_128_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                        struct isal_gcm_context_data *context_data, //!< GCM operation context data
                        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
                        const uint8_t *in, //!< Ciphertext input
                        uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief Decrypt a block of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_256_update(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
                        struct isal_gcm_context_data *context_data, //!< GCM operation context data
                        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
                        const uint8_t *in, //!< Ciphertext input
                        uint64_t len       //!< Length of data in Bytes for decryption
);

/**
 * @brief End encryption of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_128_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                              //!< multiple of 4 bytes).
                              //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End encryption of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_256_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                              //!< multiple of 4 bytes).
                              //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-128-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_128_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *auth_tag,                          //!< Authenticated Tag output
        uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a
                              //!< multiple of 4 bytes).
                              //!< Valid values are 16 (most likely), 12 or 8
);

/**
 * @brief End decryption of a AES-256-GCM Encryption message
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_256_finalize(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_pre_128(const void *key,                   //!< Pointer to key data
                 struct isal_gcm_key_data *key_data //!< GCM expanded key data
);

/**
 * @brief Pre-processes GCM key data 128 bit
 *
 * Prefills the gcm key data with key values for each round and
 * the initial sub hash key for tag encoding
 *
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_pre_256(const void *key,                   //!< Pointer to key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_128_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_256_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_128_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_256_nt(const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_128_update_nt(
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_enc_256_update_nt(
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_128_update_nt(
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
 * @requires SSE4.1 and AESNI
 */
void
_aes_gcm_dec_256_update_nt(
        const struct isal_gcm_key_data *key_data,   //!< GCM expanded key data
        struct isal_gcm_context_data *context_data, //!< GCM operation context data
        uint8_t *out,      //!< Plaintext output. Decrypt in-place is allowed.
        const uint8_t *in, //!< Ciphertext input
        uint64_t len       //!< Length of data in Bytes for decryption
);

void
_aes_gcm_precomp_128(struct isal_gcm_key_data *key_data);

void
_aes_gcm_precomp_256(struct isal_gcm_key_data *key_data);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _AES_GCM_INTERNAL_h
