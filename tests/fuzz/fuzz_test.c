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
#include <malloc.h>

#include <aes_xts.h>
#include <aes_cbc.h>
#include <aes_gcm.h>
#include <aes_keyexp.h>
#include <sha1_mb.h>
#include <mh_sha1.h>
#include <sha256_mb.h>
#include <mh_sha256.h>

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

/**
 * @brief Fill a buffer with data from a source buffer
 *
 * @param d Destination buffer
 * @param d_size Size of the destination buffer
 * @param s Source buffer
 * @param s_size Size of the source buffer
 */
static void
fill_data(void *d, const size_t d_size, const void *s, const size_t s_size)
{
        if (d == NULL || d_size == 0)
                return;

        memset(d, 0, d_size);

        if (s == NULL || s_size == 0)
                return;

        const size_t m_size = (s_size > d_size) ? d_size : s_size;
        memcpy(d, s, m_size);
}

/* AES-GCM */
static struct isal_gcm_key_data *gcm_key = NULL;     /**< GCM key data */
static struct isal_gcm_context_data *gcm_ctx = NULL; /**< GCM context data */
static uint8_t *gcm_iv = NULL;                       /**< Initialization vector */
static uint8_t *gcm_aad = NULL;                      /**< Additional authenticated data */
static uint64_t gcm_aad_len;                         /**< Length of AAD */
static uint8_t *gcm_auth_tag = NULL;                 /**< Authentication tag */
static uint64_t gcm_tag_len;                         /**< Length of the authentication tag */

/**
 * @brief Clean up all GCM resources
 *
 * Frees all allocated memory and resets all GCM-related variables.
 */
static void
gcm_end(void)
{
        if (gcm_key != NULL)
                free(gcm_key);
        if (gcm_ctx != NULL)
                free(gcm_ctx);
        if (gcm_iv != NULL)
                free(gcm_iv);
        if (gcm_aad != NULL)
                free(gcm_aad);
        if (gcm_auth_tag != NULL)
                free(gcm_auth_tag);
        gcm_key = NULL;
        gcm_ctx = NULL;
        gcm_iv = NULL;
        gcm_aad = NULL;
        gcm_aad_len = 0;
        gcm_auth_tag = NULL;
        gcm_tag_len = 0;
}

/**
 * @brief Initialize GCM resources for testing
 *
 * Allocates memory for GCM key data, initialization vector,
 * additional authenticated data, and authentication tag.
 * Then fills them with data from the provided buffer.
 *
 * @param data_size Size of the input data
 * @param data Pointer to the input data
 * @return int 0 on success, -1 on failure (memory allocation)
 */
static int
gcm_start(const size_t data_size, const uint8_t *data)
{
        gcm_key = (struct isal_gcm_key_data *) memalign(16, sizeof(struct isal_gcm_key_data));
        gcm_iv = (uint8_t *) malloc(16);
        gcm_aad_len = data_size;
        gcm_aad = (uint8_t *) malloc(gcm_aad_len);
        gcm_tag_len = data_size;
        gcm_auth_tag = (uint8_t *) malloc(gcm_tag_len);
        if (gcm_key == NULL || gcm_iv == NULL || gcm_aad == NULL || gcm_auth_tag == NULL) {
                gcm_end();
                return -1;
        }
        fill_data(gcm_key, sizeof(struct isal_gcm_key_data), data, data_size);
        fill_data(gcm_iv, 12, data, data_size);
        fill_data(gcm_aad, gcm_aad_len, data, data_size);
        fill_data(gcm_auth_tag, gcm_tag_len, data, data_size);
        return 0;
}

/**
 * @brief Test AES-128 GCM encryption
 *
 * Tests the AES-128 GCM encryption functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_enc(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_enc_128(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                                     gcm_auth_tag, gcm_tag_len);
        else
                isal_aes_gcm_enc_128_nt(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad,
                                        gcm_aad_len, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM encryption
 *
 * Tests the AES-256 GCM encryption functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_enc(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_enc_256(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                                     gcm_auth_tag, gcm_tag_len);
        else
                isal_aes_gcm_enc_256_nt(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad,
                                        gcm_aad_len, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM decryption
 *
 * Tests the AES-128 GCM decryption functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_dec(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_dec_128(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                                     gcm_auth_tag, gcm_tag_len);
        else
                isal_aes_gcm_dec_128_nt(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad,
                                        gcm_aad_len, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM decryption
 *
 * Tests the AES-256 GCM decryption functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_dec(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_dec_256(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad, gcm_aad_len,
                                     gcm_auth_tag, gcm_tag_len);
        else
                isal_aes_gcm_dec_256_nt(gcm_key, gcm_ctx, out, in, len, gcm_iv, gcm_aad,
                                        gcm_aad_len, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM initialization
 *
 * Tests the AES-128 GCM initialization functionality with the provided data.
 * This initializes the GCM context with the key, IV, and AAD.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_init(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_init_128(gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM initialization
 *
 * Tests the AES-256 GCM initialization functionality with the provided data.
 * This initializes the GCM context with the key, IV, and AAD.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_init(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_init_256(gcm_key, gcm_ctx, gcm_iv, gcm_aad, gcm_aad_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM encryption update
 *
 * Tests the AES-128 GCM encryption update functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 * This function is used for incremental encryption of data.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_enc_update(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_enc_128_update(gcm_key, gcm_ctx, out, in, len);
        else
                isal_aes_gcm_enc_128_update_nt(gcm_key, gcm_ctx, out, in, len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM encryption update
 *
 * Tests the AES-256 GCM encryption update functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 * This function is used for incremental encryption of data.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_enc_update(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_enc_256_update(gcm_key, gcm_ctx, out, in, len);
        else
                isal_aes_gcm_enc_256_update_nt(gcm_key, gcm_ctx, out, in, len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM decryption update
 *
 * Tests the AES-128 GCM decryption update functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 * This function is used for incremental decryption of data.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_dec_update(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_dec_128_update(gcm_key, gcm_ctx, out, in, len);
        else
                isal_aes_gcm_dec_128_update_nt(gcm_key, gcm_ctx, out, in, len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM decryption update
 *
 * Tests the AES-256 GCM decryption update functionality with the provided data,
 * alternating between normal and non-temporal versions based on the input.
 * This function is used for incremental decryption of data.
 *
 * @param buff Buffer containing test data and used for output
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_dec_update(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        /* Choose between "normal" and non-temporal version */
        if ((buff[0] % 2) == 0)
                isal_aes_gcm_dec_256_update(gcm_key, gcm_ctx, out, in, len);
        else
                isal_aes_gcm_dec_256_update_nt(gcm_key, gcm_ctx, out, in, len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM encryption finalization
 *
 * Tests the AES-128 GCM encryption finalization functionality,
 * which generates the authentication tag after processing all data.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_enc_finalize(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_enc_128_finalize(gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM encryption finalization
 *
 * Tests the AES-256 GCM encryption finalization functionality,
 * which generates the authentication tag after processing all data.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_enc_finalize(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_enc_256_finalize(gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-128 GCM decryption finalization
 *
 * Tests the AES-128 GCM decryption finalization functionality,
 * which verifies the authentication tag after processing all data.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_128_gcm_dec_finalize(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_dec_128_finalize(gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES-256 GCM decryption finalization
 *
 * Tests the AES-256 GCM decryption finalization functionality,
 * which verifies the authentication tag after processing all data.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_256_gcm_dec_finalize(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        uint8_t *out = buff;
        const uint8_t *in = buff;
        const uint64_t len = data_size;

        isal_aes_gcm_dec_256_finalize(gcm_key, gcm_ctx, gcm_auth_tag, gcm_tag_len);
        gcm_end();
        return 0;
}

/**
 * @brief Test AES GCM pre-computation
 *
 * Tests the AES GCM pre-computation function that computes
 * tables used in GCM operations.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_aes_gcm_pre(uint8_t *buff, const size_t data_size)
{
        if (gcm_start(data_size, buff) != 0)
                return -1;

        if (data_size >= 32)
                isal_aes_gcm_pre_256(buff, gcm_key);
        else if (data_size >= 16)
                isal_aes_gcm_pre_128(buff, gcm_key);

        gcm_end();

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

/* SHA1 multi-buffer */
static ISAL_SHA1_HASH_CTX_MGR *sha1_mgr = NULL;       /**< SHA1 multi-buffer context manager */
static ISAL_SHA1_HASH_CTX *sha1_ctx = NULL;           /**< SHA1 hash context */
static uint32_t sha1_digest[ISAL_SHA1_DIGEST_NWORDS]; /**< Output digest buffer */

/**
 * @brief Clean up SHA1 multi-buffer resources
 *
 * Frees all allocated memory for SHA1 multi-buffer operations
 * and resets the related pointers.
 */
static void
sha1_mb_end(void)
{
        if (sha1_mgr != NULL)
                free(sha1_mgr);
        if (sha1_ctx != NULL)
                free(sha1_ctx);
        sha1_mgr = NULL;
        sha1_ctx = NULL;
}

/**
 * @brief Initialize SHA1 multi-buffer resources
 *
 * Allocates memory for the SHA1 multi-buffer context manager and
 * hash context, then initializes both the context manager and hash context.
 *
 * @return int 0 on success, -1 on failure (memory allocation)
 */
static int
sha1_mb_start()
{
        sha1_mgr = (ISAL_SHA1_HASH_CTX_MGR *) malloc(sizeof(ISAL_SHA1_HASH_CTX_MGR));
        sha1_ctx = (ISAL_SHA1_HASH_CTX *) malloc(sizeof(ISAL_SHA1_HASH_CTX));

        if (sha1_mgr == NULL || sha1_ctx == NULL) {
                sha1_mb_end();
                return -1;
        }

        isal_sha1_ctx_mgr_init(sha1_mgr);
        isal_hash_ctx_init(sha1_ctx);

        return 0;
}

/**
 * @brief Test SHA1 multi-buffer initial submission
 *
 * Tests the SHA1 multi-buffer initial submission functionality.
 * This submits data with the FIRST flag, indicating the start of
 * a hashing operation.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha1_mb_submit_initial(uint8_t *buff, const size_t data_size)
{
        if (sha1_mb_start() != 0)
                return -1;

        ISAL_SHA1_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        isal_sha1_ctx_mgr_submit(sha1_mgr, sha1_ctx, &ctx_out, buffer, data_size, ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
        }

        sha1_mb_end();
        return 0;
}

/**
 * @brief Test SHA1 multi-buffer update submission
 *
 * Tests the SHA1 multi-buffer update functionality by splitting the input
 * into two parts: an initial part with the FIRST flag and a second part
 * with the UPDATE flag.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha1_mb_submit_update(uint8_t *buff, const size_t data_size)
{
        if (sha1_mb_start() != 0)
                return -1;

        ISAL_SHA1_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Split the input into two parts for separate first/update operations
        const size_t part1 = data_size / 2;
        const size_t part2 = data_size - part1;

        isal_sha1_ctx_mgr_submit(sha1_mgr, sha1_ctx, &ctx_out, buffer, part1, ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
        }

        if (part2 > 0) {
                isal_sha1_ctx_mgr_submit(sha1_mgr, ctx_out, &ctx_out,
                                         (const uint8_t *) buffer + part1, part2, ISAL_HASH_UPDATE);
                while (ctx_out == NULL) {
                        isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
                }
        }

        sha1_mb_end();
        return 0;
}

/**
 * @brief Test SHA1 multi-buffer complete submission sequence
 *
 * Tests the SHA1 multi-buffer complete functionality by splitting the input
 * into three parts: an initial part with the FIRST flag, a middle part with the
 * UPDATE flag, and a final part with the LAST flag to complete the hash operation.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha1_mb_submit_complete(uint8_t *buff, const size_t data_size)
{
        if (sha1_mb_start() != 0)
                return -1;

        ISAL_SHA1_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Split the input into parts for first/update/last operations
        const size_t part1 = data_size / 3;
        const size_t part2 = part1;
        const size_t part3 = data_size - part1 - part2;

        isal_sha1_ctx_mgr_submit(sha1_mgr, sha1_ctx, &ctx_out, buffer, part1, ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
        }

        if (part2 > 0) {
                isal_sha1_ctx_mgr_submit(sha1_mgr, ctx_out, &ctx_out,
                                         (const uint8_t *) buffer + part1, part2, ISAL_HASH_UPDATE);
                while (ctx_out == NULL) {
                        isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
                }
        }

        if (part3 > 0) {
                isal_sha1_ctx_mgr_submit(sha1_mgr, ctx_out, &ctx_out,
                                         (const uint8_t *) buffer + part1 + part2, part3,
                                         ISAL_HASH_LAST);
                while (ctx_out == NULL) {
                        isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
                }
        }

        sha1_mb_end();
        return 0;
}

/**
 * @brief Test SHA1 multi-buffer full submission
 *
 * Tests the SHA1 multi-buffer full submission functionality by processing
 * the entire buffer at once with the ENTIRE flag, which combines the
 * first, update, and last operations into a single call.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha1_mb_submit_full(uint8_t *buff, const size_t data_size)
{
        if (sha1_mb_start() != 0)
                return -1;

        ISAL_SHA1_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Process the entire buffer at once
        isal_sha1_ctx_mgr_submit(sha1_mgr, sha1_ctx, &ctx_out, buffer, data_size, ISAL_HASH_ENTIRE);
        while (ctx_out == NULL) {
                isal_sha1_ctx_mgr_flush(sha1_mgr, &ctx_out);
        }

        sha1_mb_end();
        return 0;
}

/* MH-SHA1 (multi-hash SHA1) */
static struct isal_mh_sha1_ctx *mh_sha1_ctx = NULL;     /**< MH-SHA1 context */
static uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS]; /**< Output digest buffer */

/**
 * @brief Clean up MH-SHA1 resources
 *
 * Frees allocated memory for the MH-SHA1 context.
 */
static void
mh_sha1_end(void)
{
        if (mh_sha1_ctx != NULL)
                free(mh_sha1_ctx);
        mh_sha1_ctx = NULL;
}

/**
 * @brief Initialize MH-SHA1 resources
 *
 * Allocates memory for the MH-SHA1 context and initializes it.
 *
 * @return int 0 on success, -1 on failure (memory allocation)
 */
static int
mh_sha1_start()
{
        mh_sha1_ctx = (struct isal_mh_sha1_ctx *) malloc(sizeof(struct isal_mh_sha1_ctx));
        if (mh_sha1_ctx == NULL) {
                return -1;
        }

        isal_mh_sha1_init(mh_sha1_ctx);
        return 0;
}

/**
 * @brief Test MH-SHA1 full hash sequence
 *
 * Tests the MH-SHA1 init, update, and finalize sequence with the provided data.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_mh_sha1_init_update_finalize(uint8_t *buff, const size_t data_size)
{
        if (mh_sha1_start() != 0)
                return -1;

        isal_mh_sha1_update(mh_sha1_ctx, buff, data_size);
        isal_mh_sha1_finalize(mh_sha1_ctx, mh_sha1_digest);

        mh_sha1_end();
        return 0;
}

/**
 * @brief Test MH-SHA1 chunked hash processing
 *
 * Tests the MH-SHA1 with chunked updates, processing the buffer in 64-byte chunks
 * (SHA1 block size), followed by finalization.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_mh_sha1_update_chunks(uint8_t *buff, const size_t data_size)
{
        if (mh_sha1_start() != 0)
                return -1;

        // Split the buffer into chunks
        const size_t chunk_size = 64; // SHA1 block size
        size_t offset = 0;

        while (offset < data_size) {
                const size_t process_size =
                        (offset + chunk_size <= data_size) ? chunk_size : data_size - offset;
                isal_mh_sha1_update(mh_sha1_ctx, buff + offset, process_size);
                offset += process_size;
        }

        isal_mh_sha1_finalize(mh_sha1_ctx, mh_sha1_digest);

        mh_sha1_end();
        return 0;
}

/* SHA256 multi-buffer */
static ISAL_SHA256_HASH_CTX_MGR *sha256_mgr = NULL; /**< SHA256 multi-buffer context manager */
static ISAL_SHA256_HASH_CTX *sha256_ctx = NULL;     /**< SHA256 hash context */
static uint32_t sha256_digest[ISAL_SHA256_DIGEST_NWORDS]; /**< Output digest buffer */

/**
 * @brief Clean up SHA256 multi-buffer resources
 *
 * Frees all allocated memory for SHA256 multi-buffer operations
 * and resets the related pointers.
 */
static void
sha256_mb_end(void)
{
        if (sha256_mgr != NULL)
                free(sha256_mgr);
        if (sha256_ctx != NULL)
                free(sha256_ctx);
        sha256_mgr = NULL;
        sha256_ctx = NULL;
}

/**
 * @brief Initialize SHA256 multi-buffer resources
 *
 * Allocates memory for the SHA256 multi-buffer context manager and
 * hash context, then initializes both the context manager and hash context.
 *
 * @return int 0 on success, -1 on failure (memory allocation)
 */
static int
sha256_mb_start()
{
        sha256_mgr = (ISAL_SHA256_HASH_CTX_MGR *) malloc(sizeof(ISAL_SHA256_HASH_CTX_MGR));
        sha256_ctx = (ISAL_SHA256_HASH_CTX *) malloc(sizeof(ISAL_SHA256_HASH_CTX));

        if (sha256_mgr == NULL || sha256_ctx == NULL) {
                sha256_mb_end();
                return -1;
        }

        isal_sha256_ctx_mgr_init(sha256_mgr);
        isal_hash_ctx_init(sha256_ctx);

        return 0;
}

/**
 * @brief Test SHA256 multi-buffer initial submission
 *
 * Tests the SHA256 multi-buffer initial submission functionality.
 * This submits data with the FIRST flag, indicating the start of
 * a hashing operation.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha256_mb_submit_initial(uint8_t *buff, const size_t data_size)
{
        if (sha256_mb_start() != 0)
                return -1;

        ISAL_SHA256_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        isal_sha256_ctx_mgr_submit(sha256_mgr, sha256_ctx, &ctx_out, buffer, data_size,
                                   ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
        }

        sha256_mb_end();
        return 0;
}

/**
 * @brief Test SHA256 multi-buffer update submission
 *
 * Tests the SHA256 multi-buffer update functionality by splitting the input
 * into two parts: an initial part with the FIRST flag and a second part
 * with the UPDATE flag.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha256_mb_submit_update(uint8_t *buff, const size_t data_size)
{
        if (sha256_mb_start() != 0)
                return -1;

        ISAL_SHA256_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Split the input into two parts for separate first/update operations
        const size_t part1 = data_size / 2;
        const size_t part2 = data_size - part1;

        isal_sha256_ctx_mgr_submit(sha256_mgr, sha256_ctx, &ctx_out, buffer, part1,
                                   ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
        }

        if (part2 > 0) {
                isal_sha256_ctx_mgr_submit(sha256_mgr, ctx_out, &ctx_out,
                                           (const uint8_t *) buffer + part1, part2,
                                           ISAL_HASH_UPDATE);
                while (ctx_out == NULL) {
                        isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
                }
        }

        sha256_mb_end();
        return 0;
}

/**
 * @brief Test SHA256 multi-buffer complete submission sequence
 *
 * Tests the SHA256 multi-buffer complete functionality by splitting the input
 * into three parts: an initial part with the FIRST flag, a middle part with the
 * UPDATE flag, and a final part with the LAST flag to complete the hash operation.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha256_mb_submit_complete(uint8_t *buff, const size_t data_size)
{
        if (sha256_mb_start() != 0)
                return -1;

        ISAL_SHA256_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Split the input into parts for first/update/last operations
        const size_t part1 = data_size / 3;
        const size_t part2 = part1;
        const size_t part3 = data_size - part1 - part2;

        isal_sha256_ctx_mgr_submit(sha256_mgr, sha256_ctx, &ctx_out, buffer, part1,
                                   ISAL_HASH_FIRST);
        while (ctx_out == NULL) {
                isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
        }

        if (part2 > 0) {
                isal_sha256_ctx_mgr_submit(sha256_mgr, ctx_out, &ctx_out,
                                           (const uint8_t *) buffer + part1, part2,
                                           ISAL_HASH_UPDATE);
                while (ctx_out == NULL) {
                        isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
                }
        }

        if (part3 > 0) {
                isal_sha256_ctx_mgr_submit(sha256_mgr, ctx_out, &ctx_out,
                                           (const uint8_t *) buffer + part1 + part2, part3,
                                           ISAL_HASH_LAST);
                while (ctx_out == NULL) {
                        isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
                }
        }

        sha256_mb_end();
        return 0;
}

/**
 * @brief Test SHA256 multi-buffer full submission
 *
 * Tests the SHA256 multi-buffer full submission functionality by processing
 * the entire buffer at once with the ENTIRE flag, which combines the
 * first, update, and last operations into a single call.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_sha256_mb_submit_full(uint8_t *buff, const size_t data_size)
{
        if (sha256_mb_start() != 0)
                return -1;

        ISAL_SHA256_HASH_CTX *ctx_out = NULL;
        const void *buffer = buff;

        // Process the entire buffer at once
        isal_sha256_ctx_mgr_submit(sha256_mgr, sha256_ctx, &ctx_out, buffer, data_size,
                                   ISAL_HASH_ENTIRE);
        while (ctx_out == NULL) {
                isal_sha256_ctx_mgr_flush(sha256_mgr, &ctx_out);
        }

        sha256_mb_end();
        return 0;
}

/* MH-SHA256 (multi-hash SHA256) */
static struct isal_mh_sha256_ctx *mh_sha256_ctx = NULL;     /**< MH-SHA256 context */
static uint32_t mh_sha256_digest[ISAL_SHA256_DIGEST_WORDS]; /**< Output digest buffer */

/**
 * @brief Clean up MH-SHA256 resources
 *
 * Frees all allocated memory for MH-SHA256 operations
 * and resets the related pointers.
 */
static void
mh_sha256_end(void)
{
        if (mh_sha256_ctx != NULL)
                free(mh_sha256_ctx);
        mh_sha256_ctx = NULL;
}

/**
 * @brief Initialize MH-SHA256 resources
 *
 * Allocates memory for the MH-SHA256 context and initializes it.
 *
 * @return int 0 on success, -1 on failure (memory allocation)
 */
static int
mh_sha256_start()
{
        mh_sha256_ctx = (struct isal_mh_sha256_ctx *) malloc(sizeof(struct isal_mh_sha256_ctx));
        if (mh_sha256_ctx == NULL) {
                return -1;
        }

        isal_mh_sha256_init(mh_sha256_ctx);
        return 0;
}

/**
 * @brief Test MH-SHA256 init, update, and finalize sequence
 *
 * Tests the MH-SHA256 API by initializing the context,
 * updating with the entire data buffer at once,
 * and then finalizing to produce the digest.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_mh_sha256_init_update_finalize(uint8_t *buff, const size_t data_size)
{
        if (mh_sha256_start() != 0)
                return -1;

        isal_mh_sha256_update(mh_sha256_ctx, buff, data_size);
        isal_mh_sha256_finalize(mh_sha256_ctx, mh_sha256_digest);

        mh_sha256_end();
        return 0;
}

/**
 * @brief Test MH-SHA256 with chunked data updates
 *
 * Tests the MH-SHA256 API by initializing the context,
 * updating it with multiple smaller chunks of data (each 64 bytes, which is
 * the SHA256 block size, or smaller for the last chunk), and finally
 * finalizing to produce the digest.
 *
 * @param buff Buffer containing test data
 * @param data_size Size of the buffer
 * @return int 0 on success, -1 on failure
 */
static int
test_mh_sha256_update_chunks(uint8_t *buff, const size_t data_size)
{
        if (mh_sha256_start() != 0)
                return -1;

        // Split the buffer into chunks
        const size_t chunk_size = 64; // SHA256 block size
        size_t offset = 0;

        while (offset < data_size) {
                const size_t process_size =
                        (offset + chunk_size <= data_size) ? chunk_size : data_size - offset;
                isal_mh_sha256_update(mh_sha256_ctx, buff + offset, process_size);
                offset += process_size;
        }

        isal_mh_sha256_finalize(mh_sha256_ctx, mh_sha256_digest);

        mh_sha256_end();
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
        { test_aes_gcm_pre, "test_aes_gcm_pre" },
        { test_aes_128_gcm_enc, "test_aes_128_gcm_enc" },
        { test_aes_256_gcm_enc, "test_aes_256_gcm_enc" },
        { test_aes_128_gcm_dec, "test_aes_128_gcm_dec" },
        { test_aes_256_gcm_dec, "test_aes_256_gcm_dec" },
        { test_aes_128_gcm_init, "test_aes_128_gcm_init" },
        { test_aes_256_gcm_init, "test_aes_256_gcm_init" },
        /* AES-GCM functions */
        { test_aes_128_gcm_enc_update, "test_aes_128_gcm_enc_update" },
        { test_aes_256_gcm_enc_update, "test_aes_256_gcm_enc_update" },
        { test_aes_128_gcm_dec_update, "test_aes_128_gcm_dec_update" },
        { test_aes_256_gcm_dec_update, "test_aes_256_gcm_dec_update" },
        { test_aes_128_gcm_enc_finalize, "test_aes_128_gcm_enc_finalize" },
        { test_aes_256_gcm_enc_finalize, "test_aes_256_gcm_enc_finalize" },
        { test_aes_128_gcm_dec_finalize, "test_aes_128_gcm_dec_finalize" },
        { test_aes_256_gcm_dec_finalize, "test_aes_256_gcm_dec_finalize" },
        /* SHA1 functions */
        { test_sha1_mb_submit_initial, "test_sha1_mb_submit_initial" },
        { test_sha1_mb_submit_update, "test_sha1_mb_submit_update" },
        { test_sha1_mb_submit_complete, "test_sha1_mb_submit_complete" },
        { test_sha1_mb_submit_full, "test_sha1_mb_submit_full" },
        /* SHA1 multihash functions */
        { test_mh_sha1_init_update_finalize, "test_mh_sha1_init_update_finalize" },
        { test_mh_sha1_update_chunks, "test_mh_sha1_update_chunks" },
        /* SHA256 functions */
        { test_sha256_mb_submit_initial, "test_sha256_mb_submit_initial" },
        { test_sha256_mb_submit_update, "test_sha256_mb_submit_update" },
        { test_sha256_mb_submit_complete, "test_sha256_mb_submit_complete" },
        { test_sha256_mb_submit_full, "test_sha256_mb_submit_full" },
        /* SHA256 multihash functions */
        { test_mh_sha256_init_update_finalize, "test_mh_sha256_init_update_finalize" },
        { test_mh_sha256_update_chunks, "test_mh_sha256_update_chunks" },
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
