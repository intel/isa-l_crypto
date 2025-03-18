/**********************************************************************
  Copyright(c) 2025 Intel Corporation All rights reserved.

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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <aes_xts.h>
#include <aes_cbc.h>
#include <aes_keyexp.h>

/**
 * @brief Calculate the dimension of an array
 *
 * @param _x The array to measure
 * @return Size of the array (number of elements)
 */
#define DIM(_x) (sizeof(_x) / sizeof(_x[0]))

int
LLVMFuzzerTestOneInput(const uint8_t *, const size_t);

int
LLVMFuzzerInitialize(int *, char ***);

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
        return 0;
}

/* AES-XTS */
/**
 * @brief Test AES-128 XTS encryption
 *
 * Tests the AES-128 XTS encryption functionality with the provided data.
 * XTS mode requires two keys and a tweak value, all reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_128_enc_xts(uint8_t *buff, const size_t data_size)
{
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_enc_128(k2, k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-256 XTS encryption
 *
 * Tests the AES-256 XTS encryption functionality with the provided data.
 * XTS mode requires two keys and a tweak value, all reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_256_enc_xts(uint8_t *buff, const size_t data_size)
{
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 32)
                return -1;

        isal_aes_xts_enc_256(k2, k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-128 XTS decryption
 *
 * Tests the AES-128 XTS decryption functionality with the provided data.
 * XTS mode requires two keys and a tweak value, all reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_128_dec_xts(uint8_t *buff, const size_t data_size)
{
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_dec_128(k2, k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-256 XTS decryption
 *
 * Tests the AES-256 XTS decryption functionality with the provided data.
 * XTS mode requires two keys and a tweak value, all reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_256_dec_xts(uint8_t *buff, const size_t data_size)
{
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 32)
                return -1;

        isal_aes_xts_dec_256(k2, k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-128 XTS encryption with expanded keys
 *
 * Tests the AES-128 XTS encryption functionality with pre-expanded keys.
 * This variant can be more efficient when the same key is used multiple times.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_128_enc_xts_expanded_key(uint8_t *buff, const size_t data_size)
{
        uint8_t expanded_k1[16 * 11];
        uint8_t expanded_k2[16 * 11];
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_enc_128_expanded_key(expanded_k2, expanded_k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-256 XTS encryption with expanded keys
 *
 * Tests the AES-256 XTS encryption functionality with pre-expanded keys.
 * This variant can be more efficient when the same key is used multiple times.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_256_enc_xts_expanded_key(uint8_t *buff, const size_t data_size)
{
        uint8_t expanded_k1[16 * 15];
        uint8_t expanded_k2[16 * 15];
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_enc_256_expanded_key(expanded_k2, expanded_k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-128 XTS decryption with expanded keys
 *
 * Tests the AES-128 XTS decryption functionality with pre-expanded keys.
 * This variant can be more efficient when the same key is used multiple times.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_128_dec_xts_expanded_key(uint8_t *buff, const size_t data_size)
{
        uint8_t expanded_k1[16 * 11];
        uint8_t expanded_k2[16 * 11];
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_dec_128_expanded_key(expanded_k2, expanded_k1, tweak, len, in, out);

        return 0;
}

/**
 * @brief Test AES-256 XTS decryption with expanded keys
 *
 * Tests the AES-256 XTS decryption functionality with pre-expanded keys.
 * This variant can be more efficient when the same key is used multiple times.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_256_dec_xts_expanded_key(uint8_t *buff, const size_t data_size)
{
        uint8_t expanded_k1[16 * 15];
        uint8_t expanded_k2[16 * 15];
        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint8_t *tweak = buff;
        const uint8_t *k1 = buff;
        const uint8_t *k2 = buff;
        const uint64_t len = data_size;

        if (data_size < 16)
                return -1;

        isal_aes_xts_dec_256_expanded_key(expanded_k2, expanded_k1, tweak, len, in, out);

        return 0;
}

/* AES-CBC */
/**
 * @brief Test AES-128 CBC encryption
 *
 * Tests the AES-128 CBC encryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_128_enc_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t enc_exp_key[16 * 11];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_enc_128(in, iv, enc_exp_key, out, len);

        return 0;
}

/**
 * @brief Test AES-192 CBC encryption
 *
 * Tests the AES-192 CBC encryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_192_enc_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t enc_exp_key[16 * 13];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_enc_192(in, iv, enc_exp_key, out, len);

        return 0;
}

/**
 * @brief Test AES-256 CBC encryption
 *
 * Tests the AES-256 CBC encryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_256_enc_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t enc_exp_key[16 * 15];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_enc_256(in, iv, enc_exp_key, out, len);

        return 0;
}

/**
 * @brief Test AES-128 CBC decryption
 *
 * Tests the AES-128 CBC decryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_128_dec_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t dec_exp_key[16 * 11];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_dec_128(in, iv, dec_exp_key, out, len);

        return 0;
}

/**
 * @brief Test AES-192 CBC decryption
 *
 * Tests the AES-192 CBC decryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_192_dec_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t dec_exp_key[16 * 13];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_dec_192(in, iv, dec_exp_key, out, len);

        return 0;
}

/**
 * @brief Test AES-256 CBC decryption
 *
 * Tests the AES-256 CBC decryption functionality with the provided data.
 * CBC mode requires an initialization vector (IV), reused from the input buffer.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success
 */
static int
test_aes_256_dec_cbc(uint8_t *buff, const size_t data_size)
{
        uint8_t dec_exp_key[16 * 15];

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;
        const uint8_t *iv = buff;

        isal_aes_cbc_dec_256(in, iv, dec_exp_key, out, len);

        return 0;
}

/* AES Key expansion */
/**
 * @brief Test AES-128 key expansion
 *
 * Tests the AES-128 key expansion functionality which generates the
 * round keys for encryption and decryption from a single key.
 *
 * @param buff Buffer containing the key data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_128_keyexp(uint8_t *buff, const size_t data_size)
{
        const void *key = buff;
        uint8_t enc_exp_key[16 * 11];
        uint8_t dec_exp_key[16 * 11];

        if (data_size < 16)
                return -1;

        isal_aes_keyexp_128(key, enc_exp_key, dec_exp_key);

        return 0;
}

/**
 * @brief Test AES-192 key expansion
 *
 * Tests the AES-192 key expansion functionality which generates the
 * round keys for encryption and decryption from a single key.
 *
 * @param buff Buffer containing the key data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_192_keyexp(uint8_t *buff, const size_t data_size)
{
        const void *key = buff;
        uint8_t enc_exp_key[16 * 13];
        uint8_t dec_exp_key[16 * 13];

        if (data_size < 24)
                return -1;

        isal_aes_keyexp_192(key, enc_exp_key, dec_exp_key);

        return 0;
}

/**
 * @brief Test AES-256 key expansion
 *
 * Tests the AES-256 key expansion functionality which generates the
 * round keys for encryption and decryption from a single key.
 *
 * @param buff Buffer containing the key data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure (insufficient data)
 */
static int
test_aes_256_keyexp(uint8_t *buff, const size_t data_size)
{
        const void *key = buff;
        uint8_t enc_exp_key[16 * 15];
        uint8_t dec_exp_key[16 * 15];

        if (data_size < 32)
                return -1;

        isal_aes_keyexp_256(key, enc_exp_key, dec_exp_key);

        return 0;
}

/**
 * @brief Structure defining a test function and its name
 *
 * This structure maps a test function pointer to its descriptive name.
 * It's used to build the table of API tests that will be randomly
 * selected by the fuzzer.
 */
struct {
        int (*func)(uint8_t *buff, const size_t data_size); /**< Function pointer to the test */
        const char *func_name; /**< Name of the function for debugging */
} direct_apis[] = {
        /* AES key expansion functions */
        { test_aes_128_keyexp, "test_aes_128_keyexp" },
        { test_aes_192_keyexp, "test_aes_192_keyexp" },
        { test_aes_256_keyexp, "test_aes_256_keyexp" },
        /* AES-CBC functions */
        { test_aes_128_enc_cbc, "test_aes_128_enc_cbc" },
        { test_aes_192_enc_cbc, "test_aes_192_enc_cbc" },
        { test_aes_256_enc_cbc, "test_aes_256_enc_cbc" },
        { test_aes_128_dec_cbc, "test_aes_128_dec_cbc" },
        { test_aes_192_dec_cbc, "test_aes_192_dec_cbc" },
        { test_aes_256_dec_cbc, "test_aes_256_dec_cbc" },
        /* AES-XTS functions */
        { test_aes_128_enc_xts, "test_aes_128_enc_xts" },
        { test_aes_256_enc_xts, "test_aes_256_enc_xts" },
        { test_aes_128_dec_xts, "test_aes_128_dec_xts" },
        { test_aes_256_dec_xts, "test_aes_256_dec_xts" },
        { test_aes_128_enc_xts_expanded_key, "test_aes_128_enc_xts_expanded_key" },
        { test_aes_256_enc_xts_expanded_key, "test_aes_256_enc_xts_expanded_key" },
        { test_aes_128_dec_xts_expanded_key, "test_aes_128_dec_xts_expanded_key" },
        { test_aes_256_dec_xts_expanded_key, "test_aes_256_dec_xts_expanded_key" },
};

/**
 * @brief Main fuzzer entry point for testing one input
 *
 * This function is called for each fuzzed input. It copies the input data
 * to a new buffer, selects a test function based on the first byte of the
 * input, executes the test function, and cleans up.
 *
 * @param data Pointer to the fuzzed input data
 * @param data_size Size of the fuzzed input data
 * @return int 0 on success, non-zero on failure
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, const size_t data_size)
{
        uint8_t *buff;

        buff = malloc(data_size);
        if (buff == NULL)
                return EXIT_FAILURE;
        memcpy(buff, data, data_size);

        /* Select a test function based on the first byte of the input */
        const int idx = data[0] % DIM(direct_apis);

        /* Execute the selected test function */
        direct_apis[idx].func(buff, data_size);

        free(buff);
        return 0;
}
