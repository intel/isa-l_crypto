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

/*
 * AES self tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <aes_cbc.h>
#include <aes_keyexp.h>
#include <isal_crypto_api.h>
#include <isal_self_tests.h>
#include "types.h"
#include "test.h"

struct self_test_cbc_vector {
        const uint8_t *cipher_key; /* Cipher key */
        size_t cipher_key_size;    /* Key size in bytes */
        uint8_t *cipher_iv;        /* Initialization vector */
        const uint8_t *plaintext;  /* Plaintext */
        size_t plaintext_size;     /* Plaintext length in bytes */
        const uint8_t *ciphertext; /* Ciphertext */
        const char *description;   /* Description of vector */
};

/*
 *  AES-CBC Test vectors from
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

static const uint8_t aes_cbc_128_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

static uint8_t aes_cbc_128_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t aes_cbc_128_plaintext[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
        0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
        0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t aes_cbc_128_ciphertext[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
        0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb,
        0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74,
        0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1,
        0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

static const uint8_t aes_cbc_192_key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                                           0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                                           0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };

static uint8_t aes_cbc_192_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t aes_cbc_192_plaintext[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
        0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
        0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t aes_cbc_192_ciphertext[] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f,
        0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7,
        0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a,
        0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0, 0x08, 0xb0, 0xe2, 0x79,
        0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
};

static const uint8_t aes_cbc_256_key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                                           0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                           0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                                           0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

static uint8_t aes_cbc_256_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t aes_cbc_256_plaintext[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
        0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
        0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
        0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t aes_cbc_256_ciphertext[] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
        0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f,
        0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba,
        0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2,
        0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

#define ADD_CBC_VECTOR(_key, _iv, _plain, _cipher, _descr)                                         \
        {                                                                                          \
                _key, sizeof(_key), _iv, _plain, sizeof(_plain), _cipher, _descr                   \
        }

static const struct self_test_cbc_vector cbc_vectors[] = {
        ADD_CBC_VECTOR(aes_cbc_128_key, aes_cbc_128_iv, aes_cbc_128_plaintext,
                       aes_cbc_128_ciphertext, "AES128-CBC"),
        ADD_CBC_VECTOR(aes_cbc_192_key, aes_cbc_192_iv, aes_cbc_192_plaintext,
                       aes_cbc_192_ciphertext, "AES192-CBC"),
        ADD_CBC_VECTOR(aes_cbc_256_key, aes_cbc_256_iv, aes_cbc_256_plaintext,
                       aes_cbc_256_ciphertext, "AES256-CBC"),
};

static int
cbc_self_test_vector(const struct self_test_cbc_vector *v)
{
        struct {
                DECLARE_ALIGNED(uint8_t expkey_enc[16 * 15], 16);
                DECLARE_ALIGNED(uint8_t expkey_dec[16 * 15], 16);
        } aes_keys;
        uint8_t scratch[256];

        /* message too long */
        if (v->plaintext_size > sizeof(scratch))
                return 0;

        /* test encrypt direction */
        memset(scratch, 0, sizeof(scratch));
        memcpy(scratch, v->plaintext, v->plaintext_size);

        switch (v->cipher_key_size) {
        case CBC_128_BITS:
                aes_keyexp_128(v->cipher_key, aes_keys.expkey_enc, aes_keys.expkey_dec);
                aes_cbc_enc_128(scratch, v->cipher_iv, aes_keys.expkey_enc, scratch,
                                v->plaintext_size);
                break;
        case CBC_192_BITS:
                aes_keyexp_192(v->cipher_key, aes_keys.expkey_enc, aes_keys.expkey_dec);
                aes_cbc_enc_192(scratch, v->cipher_iv, aes_keys.expkey_enc, scratch,
                                v->plaintext_size);
                break;
        case CBC_256_BITS:
                aes_keyexp_256(v->cipher_key, aes_keys.expkey_enc, aes_keys.expkey_dec);
                aes_cbc_enc_256(scratch, v->cipher_iv, aes_keys.expkey_enc, scratch,
                                v->plaintext_size);
                break;
        default:
                /* invalid key size */
                return 0;
        }

        /* check for cipher text mismatch */
        if (memcmp(scratch, v->ciphertext, v->plaintext_size))
                return 0;

        /* test decrypt direction */
        memset(scratch, 0, sizeof(scratch));
        memcpy(scratch, v->ciphertext, v->plaintext_size);

        switch (v->cipher_key_size) {
        case CBC_128_BITS:
                aes_cbc_dec_128(scratch, v->cipher_iv, aes_keys.expkey_dec, scratch,
                                v->plaintext_size);
                break;
        case CBC_192_BITS:
                aes_cbc_dec_192(scratch, v->cipher_iv, aes_keys.expkey_dec, scratch,
                                v->plaintext_size);
                break;
        case CBC_256_BITS:
                aes_cbc_dec_256(scratch, v->cipher_iv, aes_keys.expkey_dec, scratch,
                                v->plaintext_size);
                break;
        default:
                /* invalid key size */
                return 0;
        }

        /* check for plain text mismatch */
        if (memcmp(scratch, v->plaintext, v->plaintext_size))
                return 0;

        return 1;
}

int
_aes_cbc_self_test(void)
{
        static int self_tests_done = 0;
        static int previous_result = 0;

        if (self_tests_done)
                return previous_result;

        /* Only execute once */
        self_tests_done = 1;

        for (uint32_t i = 0; i < DIM(cbc_vectors); i++) {
                const struct self_test_cbc_vector *v = &cbc_vectors[i];

                if (cbc_self_test_vector(v) == 0) {
                        /* Store the result for future API calls */
                        previous_result = 1;
                        return previous_result;
                }
        }

        return 0;
}
