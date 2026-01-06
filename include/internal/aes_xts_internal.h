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
 *  @file aes_xts_internal.h
 *  @brief AES XTS encryption/decryption internal function prototypes.
 *
 */
#ifndef _AES_XTS_INTERNAL_H
#define _AES_XTS_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {

#endif

/** @brief XTS-AES-128 Encryption
 *
 * @requires AES-NI
 */

void
_XTS_AES_128_enc(uint8_t *k2,         //!<  key used for tweaking, 16 bytes
                 uint8_t *k1,         //!<  key used for encryption of tweaked plaintext, 16 bytes
                 uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
                 uint64_t N,          //!<  sector size, in bytes
                 const uint8_t *pt,   //!<  plaintext sector input data
                 uint8_t *ct          //!<  ciphertext sector output data
);

/** @brief XTS-AES-128 Encryption with pre-expanded keys
 *
 * @requires AES-NI
 */

void
_XTS_AES_128_enc_expanded_key(
        uint8_t *k2, //!<  expanded key used for tweaking, 16*11 bytes
        uint8_t *k1, //!<  expanded key used for encryption of tweaked plaintext, 16*11 bytes
        uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
        uint64_t N,          //!<  sector size, in bytes
        const uint8_t *pt,   //!<  plaintext sector input data
        uint8_t *ct          //!<  ciphertext sector output data
);

/** @brief XTS-AES-128 Decryption
 *
 * @requires AES-NI
 */

void
_XTS_AES_128_dec(uint8_t *k2,         //!<  key used for tweaking, 16 bytes
                 uint8_t *k1,         //!<  key used for decryption of tweaked ciphertext, 16 bytes
                 uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
                 uint64_t N,          //!<  sector size, in bytes
                 const uint8_t *ct,   //!<  ciphertext sector input data
                 uint8_t *pt          //!<  plaintext sector output data
);

/** @brief XTS-AES-128 Decryption with pre-expanded keys
 *
 * @requires AES-NI
 */

void
_XTS_AES_128_dec_expanded_key(
        uint8_t *k2, //!<  expanded key used for tweaking, 16*11 bytes - encryption key is used
        uint8_t *k1, //!<  expanded decryption key used for decryption of tweaked ciphertext, 16*11
                     //!<  bytes
        uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
        uint64_t N,          //!<  sector size, in bytes
        const uint8_t *ct,   //!<  ciphertext sector input data
        uint8_t *pt          //!<  plaintext sector output data
);

/** @brief XTS-AES-256 Encryption
 *
 * @requires AES-NI
 */

void
_XTS_AES_256_enc(uint8_t *k2,         //!<  key used for tweaking, 16*2 bytes
                 uint8_t *k1,         //!<  key used for encryption of tweaked plaintext, 16*2 bytes
                 uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
                 uint64_t N,          //!<  sector size, in bytes
                 const uint8_t *pt,   //!<  plaintext sector input data
                 uint8_t *ct          //!<  ciphertext sector output data
);

/** @brief XTS-AES-256 Encryption with pre-expanded keys
 *
 * @requires AES-NI
 */

void
_XTS_AES_256_enc_expanded_key(
        uint8_t *k2, //!<  expanded key used for tweaking, 16*15 bytes
        uint8_t *k1, //!<  expanded key used for encryption of tweaked plaintext, 16*15 bytes
        uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
        uint64_t N,          //!<  sector size, in bytes
        const uint8_t *pt,   //!<  plaintext sector input data
        uint8_t *ct          //!<  ciphertext sector output data
);

/** @brief XTS-AES-256 Decryption
 *
 * @requires AES-NI
 */

void
_XTS_AES_256_dec(uint8_t *k2, //!<  key used for tweaking, 16*2 bytes
                 uint8_t *k1, //!<  key used for  decryption of tweaked ciphertext, 16*2 bytes
                 uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
                 uint64_t N,          //!<  sector size, in bytes
                 const uint8_t *ct,   //!<  ciphertext sector input data
                 uint8_t *pt          //!<  plaintext sector output data
);

/** @brief XTS-AES-256 Decryption with pre-expanded keys
 *
 * @requires AES-NI
 */

void
_XTS_AES_256_dec_expanded_key(
        uint8_t *k2, //!<  expanded key used for tweaking, 16*15 bytes - encryption key is used
        uint8_t *k1, //!<  expanded decryption key used for decryption of tweaked ciphertext, 16*15
                     //!<  bytes
        uint8_t *TW_initial, //!<  initial tweak value, 16 bytes
        uint64_t N,          //!<  sector size, in bytes
        const uint8_t *ct,   //!<  ciphertext sector input data
        uint8_t *pt          //!<  plaintext sector output data
);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _AES_XTS_INTERNAL_H
