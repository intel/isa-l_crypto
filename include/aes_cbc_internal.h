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
 *  @file aes_cbc_internal.h
 *  @brief AES CBC encryption/decryption internal function prototypes.
 *
 */
#ifndef _AES_CBC_INTERNAL_H
#define _AES_CBC_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {

#endif

/** @brief CBC-AES 128 bit key Decryption
 *
 * @requires SSE4.1 and AESNI
 *
 * arg 1: in:   pointer to input (cipher text)
 * arg 2: IV:   pointer to IV, Must be 16 bytes aligned to a 16 byte boundary
 * arg 3: keys: pointer to keys, Must be on a 16 byte boundary and length of key size * key rounds
 * arg 4: OUT:  pointer to output (plain text ... in-place allowed)
 * arg 5: len_bytes:  length in bytes (multiple of 16)
 */
void
_aes_cbc_dec_128(void *in,          //!< Input cipher text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or dec_keys of cbc_key_data
                 void *out,         //!< Output plain text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 192 bit key Decryption
 *
 * @requires SSE4.1 and AESNI
 *
 */
void
_aes_cbc_dec_192(void *in,          //!< Input cipher text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or dec_keys of cbc_key_data
                 void *out,         //!< Output plain text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Decryption
 *
 * @requires SSE4.1 and AESNI
 *
 */
void
_aes_cbc_dec_256(void *in,          //!< Input cipher text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or dec_keys of cbc_key_data
                 void *out,         //!< Output plain text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 128 bit key Encryption
 *
 * @requires SSE4.1 and AESNI
 *
 * arg 1: in:   pointer to input (plain text)
 * arg 2: IV:   pointer to IV, Must be 16 bytes aligned to a 16 byte boundary
 * arg 3: keys: pointer to keys, Must be on a 16 byte boundary and length of key size * key rounds
 * arg 4: OUT:  pointer to output (cipher text ... in-place allowed)
 * arg 5: len_bytes:  length in bytes (multiple of 16)
 */
int
_aes_cbc_enc_128(void *in,          //!< Input plain text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or enc_keys of cbc_key_data
                 void *out,         //!< Output cipher text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);
/** @brief CBC-AES 192 bit key Encryption
 *
 * @requires SSE4.1 and AESNI
 *
 */
int
_aes_cbc_enc_192(void *in,          //!< Input plain text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or enc_keys of cbc_key_data
                 void *out,         //!< Output cipher text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

/** @brief CBC-AES 256 bit key Encryption
 *
 * @requires SSE4.1 and AESNI
 *
 */
int
_aes_cbc_enc_256(void *in,          //!< Input plain text
                 uint8_t *IV,       //!< Must be 16 bytes aligned to a 16 byte boundary
                 uint8_t *keys,     //!< Must be on a 16 byte boundary and length of key size * key
                                    //!< rounds or enc_keys of cbc_key_data
                 void *out,         //!< Output cipher text
                 uint64_t len_bytes //!< Must be a multiple of 16 bytes
);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _AES_CBC_INTERNAL_H
