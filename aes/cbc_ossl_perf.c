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

#include <stdio.h>
#include <stdlib.h> // for rand
#include <string.h> // for memcmp
#include <aes_cbc.h>
#include <aes_keyexp.h>
#include <test.h>
#include "ossl_helper.h"
#include "types.h"

#ifndef GT_L3_CACHE
#define GT_L3_CACHE 32 * 1024 * 1024 /* some number > last level cache */
#endif

#if !defined(COLD_TEST) && !defined(TEST_CUSTOM)
// Cached test, loop many times over small dataset
#define TEST_LEN      8 * 1024
#define TEST_LOOPS    400000
#define TEST_TYPE_STR "_warm"
#elif defined(COLD_TEST)
// Uncached test.  Pull from large mem base.
#define TEST_LEN      (2 * GT_L3_CACHE)
#define TEST_LOOPS    50
#define TEST_TYPE_STR "_cold"
#endif

#ifndef TEST_SEED
#define TEST_SEED 0x1234
#endif

static unsigned char const ic[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static unsigned char *plaintext = NULL;
static unsigned char *cbc_plaintext = NULL;
static unsigned char *ciphertext = NULL;
static unsigned char *ossl_plaintext = NULL;
static unsigned char *ossl_ciphertext = NULL;

static uint8_t test_key[CBC_256_BITS];

void
mk_rand_data(uint8_t *data, uint32_t size)
{
        unsigned int i;
        for (i = 0; i < size; i++) {
                *data++ = rand();
        }
}

int
aes_128_perf(uint8_t *key)
{
        int i, ret;

        /* Initialize our cipher context, which can use same input vectors */
        uint8_t *iv = NULL;
        struct cbc_key_data *key_data = NULL;

        ret = posix_memalign((void **) &iv, 16, (CBC_IV_DATA_LEN));
        if (ret) {
                printf("alloc error: Fail");
                return 1;
        }
        ret = posix_memalign((void **) &key_data, 16, (sizeof(*key_data)));
        if (ret) {
                printf("alloc error: Fail");
                ret = 1;
                goto exit;
        }

        memcpy(iv, ic, CBC_IV_DATA_LEN);

        isal_aes_keyexp_128(key, key_data->enc_keys, key_data->dec_keys);
        isal_aes_cbc_enc_128(plaintext, iv, key_data->enc_keys, ciphertext, TEST_LEN);
        openssl_aes_128_cbc_enc(key, iv, TEST_LEN, plaintext, ossl_ciphertext);

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_enc_128(plaintext, iv, key_data->enc_keys, plaintext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_128_encode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_128_cbc_enc(key, iv, TEST_LEN, plaintext, plaintext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_128_encode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_dec_128(ciphertext, iv, key_data->dec_keys, cbc_plaintext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_128_decode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_128_cbc_dec(key, iv, TEST_LEN, ossl_ciphertext, ossl_plaintext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_128_decode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        printf("\n");

        ret = 0;
exit:
        aligned_free(iv);
        aligned_free(key_data);

        return ret;
}

int
aes_192_perf(uint8_t *key)
{
        int i, ret;
        uint8_t *iv = NULL;
        struct cbc_key_data *key_data = NULL;

        ret = posix_memalign((void **) &iv, 16, (CBC_IV_DATA_LEN));
        if (ret) {
                printf("alloc error: Fail");
                return 1;
        }
        ret = posix_memalign((void **) &key_data, 16, (sizeof(*key_data)));
        if (ret) {
                printf("alloc error: Fail");
                ret = 1;
                goto exit;
        }

        memcpy(iv, ic, CBC_IV_DATA_LEN);
        isal_aes_keyexp_192(key, key_data->enc_keys, key_data->dec_keys);
        isal_aes_cbc_enc_192(plaintext, iv, key_data->enc_keys, ciphertext, TEST_LEN);
        openssl_aes_192_cbc_enc(key, iv, TEST_LEN, plaintext, ossl_ciphertext);

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_enc_192(plaintext, iv, key_data->enc_keys, ciphertext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_192_encode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_192_cbc_enc(key, iv, TEST_LEN, plaintext, ossl_ciphertext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_192_encode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_dec_192(ciphertext, iv, key_data->dec_keys, cbc_plaintext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_192_decode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_192_cbc_dec(key, iv, TEST_LEN, ossl_ciphertext, ossl_plaintext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_192_decode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        printf("\n");

        ret = 0;
exit:
        aligned_free(iv);
        aligned_free(key_data);

        return ret;
}

int
aes_256_perf(uint8_t *key)
{
        int i, ret;
        uint8_t *iv = NULL;
        struct cbc_key_data *key_data = NULL;

        ret = posix_memalign((void **) &iv, 16, (CBC_IV_DATA_LEN));
        if (ret) {
                printf("alloc error: Fail");
                return 1;
        }
        ret = posix_memalign((void **) &key_data, 16, (sizeof(*key_data)));
        if (ret) {
                printf("alloc error: Fail");
                ret = 1;
                goto exit;
        }

        isal_aes_keyexp_256(key, key_data->enc_keys, key_data->dec_keys);
        memcpy(iv, ic, CBC_IV_DATA_LEN);
        isal_aes_cbc_enc_256(plaintext, iv, key_data->enc_keys, ciphertext, TEST_LEN);
        openssl_aes_256_cbc_enc(key, iv, TEST_LEN, plaintext, ossl_ciphertext);

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_enc_256(plaintext, iv, key_data->enc_keys, ciphertext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_256_encode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_256_cbc_enc(key, iv, TEST_LEN, plaintext, ossl_ciphertext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_256_encode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }

        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        isal_aes_cbc_dec_256(ciphertext, iv, key_data->dec_keys, cbc_plaintext,
                                             TEST_LEN);
                }

                perf_stop(&stop);
                printf("ISA-L__aes_cbc_256_decode" TEST_TYPE_STR ":  ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        {
                struct perf start, stop;

                perf_start(&start);
                for (i = 0; i < TEST_LOOPS; i++) {
                        openssl_aes_256_cbc_dec(key, iv, TEST_LEN, ossl_ciphertext, ossl_plaintext);
                }

                perf_stop(&stop);
                printf("OpenSSL_aes_cbc_256_decode" TEST_TYPE_STR ": ");
                perf_print(stop, start, (long long) TEST_LEN * i);
        }
        printf("\n");

        ret = 0;
exit:
        aligned_free(iv);
        aligned_free(key_data);

        return ret;
}

int
main(void)
{
        int fail = 0;

        srand(TEST_SEED);

        plaintext = malloc(TEST_LEN);
        cbc_plaintext = malloc(TEST_LEN);
        ciphertext = malloc(TEST_LEN);
        ossl_plaintext = malloc(TEST_LEN);
        ossl_ciphertext = malloc(TEST_LEN);
        if (NULL == plaintext || NULL == ciphertext || NULL == cbc_plaintext ||
            NULL == ossl_plaintext || NULL == ossl_ciphertext) {
                printf("malloc of testsize:0x%x failed\n", TEST_LEN);
                fail = 1;
                goto exit;
        }

        mk_rand_data(plaintext, TEST_LEN);
        mk_rand_data(test_key, sizeof(test_key));
        printf("AES CBC ISA-L vs OpenSSL performance:\n");
        fail += aes_128_perf(test_key);
        fail += aes_192_perf(test_key);
        fail += aes_256_perf(test_key);

exit:
        free(plaintext);
        free(cbc_plaintext);
        free(ciphertext);
        free(ossl_plaintext);
        free(ossl_ciphertext);

        return fail;
}
