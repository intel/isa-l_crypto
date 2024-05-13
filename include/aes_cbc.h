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

/**
 *  @file aes_cbc.h
 *  @brief AES CBC encryption/decryption function prototypes.
 *
 */
#ifndef _AES_CBC_h
#define _AES_CBC_h

#include <stdint.h>

#include "types.h"

#ifdef __cplusplus
extern "C" {

#endif

typedef enum cbc_key_size { CBC_128_BITS = 16, CBC_192_BITS = 24, CBC_256_BITS = 32 } cbc_key_size;
#define CBC_ROUND_KEY_LEN  (16)
#define CBC_128_KEY_ROUNDS (10 + 1) /*expanded key holds 10 key rounds plus original key*/
#define CBC_192_KEY_ROUNDS (12 + 1) /*expanded key holds 12 key rounds plus original key*/
#define CBC_256_KEY_ROUNDS (14 + 1) /*expanded key holds 14 key rounds plus original key*/
#define CBC_MAX_KEYS_SIZE  (CBC_ROUND_KEY_LEN * CBC_256_KEY_ROUNDS)

#define CBC_IV_DATA_LEN (16)

/** @brief holds intermediate key data used in encryption/decryption
 *
 */
struct cbc_key_data { // must be 16 byte aligned
        uint8_t enc_keys[CBC_MAX_KEYS_SIZE];
        uint8_t dec_keys[CBC_MAX_KEYS_SIZE];
};

/** @brief CBC-AES key pre-computation done once for a key
 *
 * @deprecated Please use isal_aes_keyexp_128(), isal_aes_keyexp_192() or isal_aes_keyexp_256()
 * instead.
 * @requires SSE4.1 and AESNI
 *
 * arg 1: in:   pointer to key
 * arg 2: OUT:  pointer to a key expanded data
 */
ISAL_DEPRECATED(
        "Please use isal_aes_keyexp_128(), isal_aes_keyexp_192() or isal_aes_keyexp_256() instead")
int
aes_cbc_precomp(uint8_t *key, int key_size, struct cbc_key_data *keys_blk);

/** @brief CBC-AES 128 bit key Decryption
 *
 * @deprecated Please use isal_aes_cbc_dec_128() instead.
 * @requires SSE4.1 and AESNI
 *
 * arg 1: in:   pointer to input (cipher text)
 * arg 2: IV:   pointer to IV, Must be 16 bytes aligned to a 16 byte boundary
 * arg 3: keys: pointer to keys, Must be on a 16 byte boundary and length of key size * key rounds
 * arg 4: OUT:  pointer to output (plain text ... in-place allowed)
 * arg 5: len_bytes:  length in bytes (multiple of 16)
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_dec_128() instead")
void
aes_cbc_dec_128(void *in,          //!< Input cipher text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or dec_keys of cbc_key_data
                void *out,         //!< Output plain text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 192 bit key Decryption
 *
 * @deprecated Please use isal_aes_cbc_dec_192() instead.
 * @requires SSE4.1 and AESNI
 *
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_dec_192() instead")
void
aes_cbc_dec_192(void *in,          //!< Input cipher text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or dec_keys of cbc_key_data
                void *out,         //!< Output plain text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Decryption
 *
 * @deprecated Please use isal_aes_cbc_dec_256() instead.
 * @requires SSE4.1 and AESNI
 *
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_dec_256() instead")
void
aes_cbc_dec_256(void *in,          //!< Input cipher text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or dec_keys of cbc_key_data
                void *out,         //!< Output plain text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 128 bit key Encryption
 *
 * @deprecated Please use isal_aes_cbc_enc_128() instead.
 * @requires SSE4.1 and AESNI
 *
 * arg 1: in:   pointer to input (plain text)
 * arg 2: IV:   pointer to IV, Must be 16 bytes aligned to a 16 byte boundary
 * arg 3: keys: pointer to keys, Must be on a 16 byte boundary and length of key size * key rounds
 * arg 4: OUT:  pointer to output (cipher text ... in-place allowed)
 * arg 5: len_bytes:  length in bytes (multiple of 16)
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_enc_128() instead")
int
aes_cbc_enc_128(void *in,          //!< Input plain text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or enc_keys of cbc_key_data
                void *out,         //!< Output cipher text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);
/** @brief CBC-AES 192 bit key Encryption
 *
 * @deprecated Please use isal_aes_cbc_enc_192() instead.
 * @requires SSE4.1 and AESNI
 *
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_enc_192() instead")
int
aes_cbc_enc_192(void *in,          //!< Input plain text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or enc_keys of cbc_key_data
                void *out,         //!< Output cipher text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Encryption
 *
 * @deprecated Please use isal_aes_cbc_enc_256() instead.
 * @requires SSE4.1 and AESNI
 *
 */
ISAL_DEPRECATED("Please use isal_aes_cbc_enc_256() instead")
int
aes_cbc_enc_256(void *in,          //!< Input plain text
                uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                   //!< rounds or enc_keys of cbc_key_data
                void *out,         //!< Output cipher text
                uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 128 bit key Decryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_dec_128(const void *in,   //!< Input ciphertext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output plaintext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);

/** @brief CBC-AES 192 bit key Decryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_dec_192(const void *in,   //!< Input ciphertext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output plaintext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Decryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_dec_256(const void *in,   //!< Input ciphertext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output plaintext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);

/** @brief CBC-AES 128 bit key Encryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 *
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_enc_128(const void *in,   //!< Input plaintext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output ciphertext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);
/** @brief CBC-AES 192 bit key Encryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_enc_192(const void *in,   //!< Input plaintext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output ciphertext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Encryption
 *
 * @requires AES extensions and SSE4.1 for x86 or ASIMD for ARM
 * @return  Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_aes_cbc_enc_256(const void *in,   //!< Input plaintext
                     const void *iv,   //!< Initialization vector. Must be 16 bytes aligned.
                     const void *keys, //!< Expanded decryption keys. Must be on a 16 byte boundary.
                     void *out,        //!< Output ciphertext
                     const uint64_t len_bytes //!< Input length. Must be a multiple of 16 bytes
);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _AES_CBC_h
