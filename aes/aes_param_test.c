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

#include <stdio.h>
#include <string.h>

#include "isal_crypto_api.h"
#include "aes_keyexp.h"
#include "aes_cbc.h"
#include "aes_xts.h"
#include "aes_gcm.h"
#include "test.h"
#include "aes/gcm_vectors.h"

#ifdef SAFE_PARAM
#define CHECK_RETURN(state, expected, func)                                                        \
        do {                                                                                       \
                if ((state) != (expected)) {                                                       \
                        printf("test: %s() - expected return "                                     \
                               "value %d, got %d\n",                                               \
                               func, expected, state);                                             \
                        return 1;                                                                  \
                }                                                                                  \
        } while (0)

typedef int (*aes_keyexp_func)(const uint8_t *, uint8_t *, uint8_t *);
typedef int (*aes_cbc_func)(const void *, const void *, const void *, void *, const uint64_t);
typedef int (*aes_xts_func)(const uint8_t *, const uint8_t *, const uint8_t *, const uint64_t,
                            const void *, void *);
typedef int (*aes_gcm_func)(const struct isal_gcm_key_data *, struct isal_gcm_context_data *,
                            uint8_t *, const uint8_t *, const uint64_t, const uint8_t *,
                            const uint8_t *, const uint64_t, uint8_t *, const uint64_t);
typedef int (*aes_gcm_init_func)(const struct isal_gcm_key_data *, struct isal_gcm_context_data *,
                                 const uint8_t *, const uint8_t *, const uint64_t);
typedef int (*aes_gcm_update_func)(const struct isal_gcm_key_data *, struct isal_gcm_context_data *,
                                   uint8_t *, const uint8_t *, const uint64_t);
typedef int (*aes_gcm_finalize_func)(const struct isal_gcm_key_data *,
                                     struct isal_gcm_context_data *, uint8_t *, const uint64_t);
typedef int (*aes_gcm_pre_func)(const void *, struct isal_gcm_key_data *);

struct test_func {
        union {
                aes_keyexp_func keyexp_func_ptr;
                aes_cbc_func cbc_func_ptr;
                aes_xts_func xts_func_ptr;
                aes_gcm_func gcm_func_ptr;
                aes_gcm_init_func gcm_init_func_ptr;
                aes_gcm_update_func gcm_update_func_ptr;
                aes_gcm_finalize_func gcm_finalize_func_ptr;
                aes_gcm_pre_func gcm_pre_func_ptr;
        };
        char *func_name;
};

static int
test_aes_keyexp_api(aes_keyexp_func aes_keyexp_func_ptr, const char *name)
{
        uint8_t key[ISAL_CBC_ROUND_KEY_LEN] = { 0 };
        uint8_t enc_keys[ISAL_CBC_MAX_KEYS_SIZE] = { 0 };
        uint8_t dec_keys[ISAL_CBC_MAX_KEYS_SIZE] = { 0 };

        // test null key
        CHECK_RETURN(aes_keyexp_func_ptr(NULL, enc_keys, dec_keys), ISAL_CRYPTO_ERR_NULL_KEY, name);

        // test null exp key ptr
        CHECK_RETURN(aes_keyexp_func_ptr(key, NULL, dec_keys), ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null exp key ptr
        CHECK_RETURN(aes_keyexp_func_ptr(key, enc_keys, NULL), ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test valid params
        CHECK_RETURN(aes_keyexp_func_ptr(key, enc_keys, dec_keys), ISAL_CRYPTO_ERR_NONE, name);

        return 0;
}

static int
test_aes_cbc_api(aes_cbc_func aes_cbc_func_ptr, const char *name)
{
        uint8_t exp_keys[ISAL_CBC_MAX_KEYS_SIZE] = { 0 };
        uint8_t buf[16] = { 0 };
        uint8_t iv[16] = { 0 };

        // test null input ptr
        CHECK_RETURN(aes_cbc_func_ptr(NULL, iv, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NULL_SRC, name);

        // test null IV ptr
        CHECK_RETURN(aes_cbc_func_ptr(buf, NULL, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NULL_IV, name);

        // test null exp key ptr
        CHECK_RETURN(aes_cbc_func_ptr(buf, iv, NULL, buf, 16), ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null output ptr
        CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, NULL, 16), ISAL_CRYPTO_ERR_NULL_DST, name);

        // test invalid length (not multiple of 16 bytes)
        CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, buf, 15), ISAL_CRYPTO_ERR_CIPH_LEN, name);

        // test valid params
        CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NONE, name);

        return 0;
}

static int
test_aes_xts_api(aes_xts_func aes_xts_func_ptr, const char *name, const int expanded_key)
{
        uint8_t key1[32] = { 0 };
        uint8_t exp_keys1[ISAL_CBC_MAX_KEYS_SIZE] = { 0 };
        uint8_t key2[32];
        uint8_t exp_keys2[ISAL_CBC_MAX_KEYS_SIZE];
        uint8_t buf[16] = { 0 };
        uint8_t tweak[16] = { 0 };

        uint8_t *key1_ptr = (expanded_key) ? exp_keys1 : key1;
        uint8_t *key2_ptr = (expanded_key) ? exp_keys2 : key2;

        /* Key1 and key2 must be different, to avoid error */
        memset(key2, 0xff, sizeof(key2));
        memset(exp_keys2, 0xff, sizeof(exp_keys2));

        if (expanded_key) {
                // test null expanded key ptr
                CHECK_RETURN(aes_xts_func_ptr(NULL, exp_keys1, tweak, 16, buf, buf),
                             ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);
                CHECK_RETURN(aes_xts_func_ptr(exp_keys1, NULL, tweak, 16, buf, buf),
                             ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);
        } else {
                CHECK_RETURN(aes_xts_func_ptr(NULL, key2, tweak, 16, buf, buf),
                             ISAL_CRYPTO_ERR_NULL_KEY, name);
                CHECK_RETURN(aes_xts_func_ptr(key1, NULL, tweak, 16, buf, buf),
                             ISAL_CRYPTO_ERR_NULL_KEY, name);
        }

        // test null tweak ptr
        CHECK_RETURN(aes_xts_func_ptr(key1_ptr, key2_ptr, NULL, 16, buf, buf),
                     ISAL_CRYPTO_ERR_XTS_NULL_TWEAK, name);

        // test invalid length (outside range)
        CHECK_RETURN(
                aes_xts_func_ptr(key1_ptr, key2_ptr, tweak, ISAL_AES_XTS_MIN_LEN - 1, buf, buf),
                ISAL_CRYPTO_ERR_CIPH_LEN, name);

        CHECK_RETURN(
                aes_xts_func_ptr(key1_ptr, key2_ptr, tweak, ISAL_AES_XTS_MAX_LEN + 1, buf, buf),
                ISAL_CRYPTO_ERR_CIPH_LEN, name);

        // test null input ptr
        CHECK_RETURN(aes_xts_func_ptr(key1_ptr, key2_ptr, tweak, 16, NULL, buf),
                     ISAL_CRYPTO_ERR_NULL_SRC, name);

        // test null output ptr
        CHECK_RETURN(aes_xts_func_ptr(key1_ptr, key2_ptr, tweak, 16, buf, NULL),
                     ISAL_CRYPTO_ERR_NULL_DST, name);

#ifdef FIPS_MODE
        // test same key error
        CHECK_RETURN(aes_xts_func_ptr(key1_ptr, key1_ptr, tweak, 16, buf, buf),
                     ISAL_CRYPTO_ERR_XTS_SAME_KEYS, name);
#endif
        // test valid params
        CHECK_RETURN(aes_xts_func_ptr(key1_ptr, key2_ptr, tweak, 16, buf, buf),
                     ISAL_CRYPTO_ERR_NONE, name);

        return 0;
}

static int
test_aes_gcm_api(aes_gcm_func aes_gcm_func_ptr, const char *name)
{
        struct isal_gcm_key_data gkey;
        struct isal_gcm_context_data gctx;
        uint8_t buf[256] = { 0 };
        uint8_t iv[ISAL_GCM_IV_LEN] = { 0 };
        uint8_t *aad = buf;
        uint8_t *tag = buf;

        // test null key data
        CHECK_RETURN(aes_gcm_func_ptr(NULL, &gctx, buf, buf, sizeof(buf), iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null context
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, NULL, buf, buf, sizeof(buf), iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_CTX, name);

        // test null dst
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, buf, sizeof(buf), iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_DST, name);

        // test null dst with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, buf, 0, iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NONE, name);

        // test null src
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, NULL, sizeof(buf), iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_SRC, name);

        // test null src with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, NULL, 0, iv, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NONE, name);

        // test invalid len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, ISAL_GCM_MAX_LEN + 1, iv, aad, 16,
                                      tag, ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_CIPH_LEN, name);

        // test zero len
        CHECK_RETURN(
                aes_gcm_func_ptr(&gkey, &gctx, buf, buf, 0, iv, aad, 16, tag, ISAL_GCM_MAX_TAG_LEN),
                ISAL_CRYPTO_ERR_NONE, name);

        // test null iv
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), NULL, aad, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_IV, name);

        // test null aad
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), iv, NULL, 16, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_AAD, name);

        // test null aad with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), iv, NULL, 0, tag,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NONE, name);

        // test null tag
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), iv, aad, 16, NULL,
                                      ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_AUTH, name);

        // test auth tag lens
        for (int i = 5; i <= ISAL_GCM_MAX_TAG_LEN + 1; i++)
                if (i % 4 == 0)
                        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), iv, aad,
                                                      16, tag, i),
                                     ISAL_CRYPTO_ERR_NONE, name);
                else
                        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, sizeof(buf), iv, aad,
                                                      16, tag, i),
                                     ISAL_CRYPTO_ERR_AUTH_TAG_LEN, name);
        return 0;
}

static int
test_aes_gcm_init_api(aes_gcm_init_func aes_gcm_func_ptr, const char *name)
{
        struct isal_gcm_key_data gkey;
        struct isal_gcm_context_data gctx;
        uint8_t iv[ISAL_GCM_IV_LEN] = { 0 };
        uint8_t aad[64] = { 0 };

        // test null key data
        CHECK_RETURN(aes_gcm_func_ptr(NULL, &gctx, iv, aad, sizeof(aad)),
                     ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null context
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, NULL, iv, aad, sizeof(aad)), ISAL_CRYPTO_ERR_NULL_CTX,
                     name);

        // test null iv
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, aad, sizeof(aad)),
                     ISAL_CRYPTO_ERR_NULL_IV, name);

        // test null aad
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, iv, NULL, sizeof(aad)),
                     ISAL_CRYPTO_ERR_NULL_AAD, name);

        // test null aad with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, iv, aad, 0), ISAL_CRYPTO_ERR_NONE, name);

        return 0;
}

static int
test_aes_gcm_update_api(aes_gcm_update_func aes_gcm_func_ptr, const char *name)
{
        struct isal_gcm_key_data gkey;
        struct isal_gcm_context_data gctx;
        uint8_t buf[256] = { 0 };

        // test null key data
        CHECK_RETURN(aes_gcm_func_ptr(NULL, &gctx, buf, buf, sizeof(buf)),
                     ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null context
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, NULL, buf, buf, sizeof(buf)), ISAL_CRYPTO_ERR_NULL_CTX,
                     name);

        // test null dst
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, buf, sizeof(buf)),
                     ISAL_CRYPTO_ERR_NULL_DST, name);

        // test null dst with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, buf, 0), ISAL_CRYPTO_ERR_NONE, name);

        // test null src
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, NULL, sizeof(buf)),
                     ISAL_CRYPTO_ERR_NULL_SRC, name);

        // test null src with zero len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, NULL, 0), ISAL_CRYPTO_ERR_NONE, name);

        // test invalid len
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, buf, buf, ISAL_GCM_MAX_LEN + 1),
                     ISAL_CRYPTO_ERR_CIPH_LEN, name);

        return 0;
}

static int
test_aes_gcm_finalize_api(aes_gcm_finalize_func aes_gcm_func_ptr, const char *name,
                          const gcm_key_size key_size)
{
        struct isal_gcm_key_data gkey = { 0 };
        struct isal_gcm_context_data gctx = { 0 };
        uint8_t tag[ISAL_GCM_MAX_TAG_LEN] = { 0 };
        uint8_t iv[ISAL_GCM_IV_LEN] = { 0 };
        uint8_t aad[64] = { 0 };

        // init required for valid cases
        if (key_size == BITS_128)
                isal_aes_gcm_init_128(&gkey, &gctx, iv, aad, sizeof(aad));
        else
                isal_aes_gcm_init_256(&gkey, &gctx, iv, aad, sizeof(aad));

        // test null key data
        CHECK_RETURN(aes_gcm_func_ptr(NULL, &gctx, tag, ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test null context
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, NULL, tag, ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_CTX, name);

        // test null tag
        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, NULL, ISAL_GCM_MAX_TAG_LEN),
                     ISAL_CRYPTO_ERR_NULL_AUTH, name);

        // test auth tag lens
        for (int i = 5; i <= ISAL_GCM_MAX_TAG_LEN + 1; i++)
                if (i % 4 == 0)
                        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, tag, i), ISAL_CRYPTO_ERR_NONE,
                                     name);
                else
                        CHECK_RETURN(aes_gcm_func_ptr(&gkey, &gctx, tag, i),
                                     ISAL_CRYPTO_ERR_AUTH_TAG_LEN, name);
        return 0;
}

static int
test_aes_gcm_pre_api(aes_gcm_pre_func aes_gcm_func_ptr, const char *name)
{
        struct isal_gcm_key_data gkey;
        int key[8] = { 0 };

        // test null key
        CHECK_RETURN(aes_gcm_func_ptr(NULL, &gkey), ISAL_CRYPTO_ERR_NULL_KEY, name);

        // test null key data
        CHECK_RETURN(aes_gcm_func_ptr(key, NULL), ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

        // test valid params
        CHECK_RETURN(aes_gcm_func_ptr(key, &gkey), ISAL_CRYPTO_ERR_NONE, name);

        return 0;
}

#endif /* SAFE_PARAM */

int
main(void)
{
        int fail = 0;
#ifdef SAFE_PARAM
        /* Test AES key expansion API */
        const struct test_func keyexp_test_funcs[] = {
                { .keyexp_func_ptr = isal_aes_keyexp_128, "isal_aes_keyexp_128" },
                { .keyexp_func_ptr = isal_aes_keyexp_192, "isal_aes_keyexp_192" },
                { .keyexp_func_ptr = isal_aes_keyexp_256, "isal_aes_keyexp_256" },
        };

        for (int i = 0; i < DIM(keyexp_test_funcs); i++) {
                fail |= test_aes_keyexp_api(keyexp_test_funcs[i].keyexp_func_ptr,
                                            keyexp_test_funcs[i].func_name);
        }

        /* Test AES-CBC API */
        const struct test_func cbc_test_funcs[] = {
                { .cbc_func_ptr = isal_aes_cbc_enc_128, "isal_aes_cbc_enc_128" },
                { .cbc_func_ptr = isal_aes_cbc_enc_192, "isal_aes_cbc_enc_192" },
                { .cbc_func_ptr = isal_aes_cbc_enc_256, "isal_aes_cbc_enc_256" },
                { .cbc_func_ptr = isal_aes_cbc_dec_128, "isal_aes_cbc_dec_128" },
                { .cbc_func_ptr = isal_aes_cbc_dec_192, "isal_aes_cbc_dec_192" },
                { .cbc_func_ptr = isal_aes_cbc_dec_256, "isal_aes_cbc_dec_256" },
        };

        for (int i = 0; i < DIM(cbc_test_funcs); i++) {
                fail |= test_aes_cbc_api(cbc_test_funcs[i].cbc_func_ptr,
                                         cbc_test_funcs[i].func_name);
        }

        /* Test AES-XTS API */
        const struct test_func xts_test_funcs[] = {
                { .xts_func_ptr = isal_aes_xts_enc_128, "isal_aes_xts_enc_128" },
                { .xts_func_ptr = isal_aes_xts_enc_256, "isal_aes_xts_enc_256" },
                { .xts_func_ptr = isal_aes_xts_dec_128, "isal_aes_xts_dec_128" },
                { .xts_func_ptr = isal_aes_xts_dec_256, "isal_aes_xts_dec_256" },
        };

        for (int i = 0; i < DIM(xts_test_funcs); i++) {
                fail |= test_aes_xts_api(xts_test_funcs[i].xts_func_ptr,
                                         xts_test_funcs[i].func_name, 0);
        }
        /* Test AES-XTS expanded key API */
        const struct test_func xts_exp_test_funcs[] = {
                { .xts_func_ptr = isal_aes_xts_enc_128_expanded_key,
                  "isal_aes_xts_enc_128_expanded_key" },
                { .xts_func_ptr = isal_aes_xts_enc_256_expanded_key,
                  "isal_aes_xts_enc_256_expanded_key" },
                { .xts_func_ptr = isal_aes_xts_dec_128_expanded_key,
                  "isal_aes_xts_dec_128_expanded_key" },
                { .xts_func_ptr = isal_aes_xts_dec_256_expanded_key,
                  "isal_aes_xts_dec_256_expanded_key" },
        };

        for (int i = 0; i < DIM(xts_exp_test_funcs); i++) {
                fail |= test_aes_xts_api(xts_exp_test_funcs[i].xts_func_ptr,
                                         xts_exp_test_funcs[i].func_name, 1);
        }

        /* Test AES-GCM enc / dec API */
        const struct test_func gcm_test_funcs[] = {
                { .gcm_func_ptr = isal_aes_gcm_enc_128, "isal_aes_gcm_enc_128" },
                { .gcm_func_ptr = isal_aes_gcm_enc_256, "isal_aes_gcm_enc_256" },
                { .gcm_func_ptr = isal_aes_gcm_dec_128, "isal_aes_gcm_dec_128" },
                { .gcm_func_ptr = isal_aes_gcm_dec_256, "isal_aes_gcm_dec_256" },
                { .gcm_func_ptr = isal_aes_gcm_enc_128_nt, "isal_aes_gcm_enc_128_nt" },
                { .gcm_func_ptr = isal_aes_gcm_enc_256_nt, "isal_aes_gcm_enc_256_nt" },
                { .gcm_func_ptr = isal_aes_gcm_dec_128_nt, "isal_aes_gcm_dec_128_nt" },
                { .gcm_func_ptr = isal_aes_gcm_dec_256_nt, "isal_aes_gcm_dec_256_nt" },
        };

        for (int i = 0; i < DIM(gcm_test_funcs); i++) {
                fail |= test_aes_gcm_api(gcm_test_funcs[i].gcm_func_ptr,
                                         gcm_test_funcs[i].func_name);
        }

        /* Test AES-GCM init API */
        const struct test_func gcm_init_test_funcs[] = {
                { .gcm_init_func_ptr = isal_aes_gcm_init_128, "isal_aes_gcm_init_128" },
                { .gcm_init_func_ptr = isal_aes_gcm_init_256, "isal_aes_gcm_init_256" },
        };

        for (int i = 0; i < DIM(gcm_init_test_funcs); i++) {
                fail |= test_aes_gcm_init_api(gcm_init_test_funcs[i].gcm_init_func_ptr,
                                              gcm_init_test_funcs[i].func_name);
        }

        /* Test AES-GCM update API */
        const struct test_func gcm_update_test_funcs[] = {
                { .gcm_update_func_ptr = isal_aes_gcm_enc_128_update,
                  "isal_aes_gcm_enc_128_update" },
                { .gcm_update_func_ptr = isal_aes_gcm_enc_256_update,
                  "isal_aes_gcm_enc_256_update" },
                { .gcm_update_func_ptr = isal_aes_gcm_dec_128_update,
                  "isal_aes_gcm_dec_128_update" },
                { .gcm_update_func_ptr = isal_aes_gcm_dec_256_update,
                  "isal_aes_gcm_dec_256_update" },
                { .gcm_update_func_ptr = isal_aes_gcm_enc_128_update_nt,
                  "isal_aes_gcm_enc_128_update_nt" },
                { .gcm_update_func_ptr = isal_aes_gcm_enc_256_update_nt,
                  "isal_aes_gcm_enc_256_update_nt" },
                { .gcm_update_func_ptr = isal_aes_gcm_dec_128_update_nt,
                  "isal_aes_gcm_dec_128_update_nt" },
                { .gcm_update_func_ptr = isal_aes_gcm_dec_256_update_nt,
                  "isal_aes_gcm_dec_256_update_nt" },
        };

        for (int i = 0; i < DIM(gcm_update_test_funcs); i++) {
                fail |= test_aes_gcm_update_api(gcm_update_test_funcs[i].gcm_update_func_ptr,
                                                gcm_update_test_funcs[i].func_name);
        }

        /* Test AES-GCM finalize API */
        const struct test_func gcm_finalize_128_test_funcs[] = {
                { .gcm_finalize_func_ptr = isal_aes_gcm_enc_128_finalize,
                  "isal_aes_gcm_enc_128_finalize" },
                { .gcm_finalize_func_ptr = isal_aes_gcm_dec_128_finalize,
                  "isal_aes_gcm_dec_128_finalize" },
        };

        for (int i = 0; i < DIM(gcm_finalize_128_test_funcs); i++) {
                fail |= test_aes_gcm_finalize_api(
                        gcm_finalize_128_test_funcs[i].gcm_finalize_func_ptr,
                        gcm_finalize_128_test_funcs[i].func_name, BITS_128);
        }

        const struct test_func gcm_finalize_256_test_funcs[] = {
                { .gcm_finalize_func_ptr = isal_aes_gcm_enc_256_finalize,
                  "isal_aes_gcm_enc_256_finalize" },
                { .gcm_finalize_func_ptr = isal_aes_gcm_dec_256_finalize,
                  "isal_aes_gcm_dec_256_finalize" },
        };

        for (int i = 0; i < DIM(gcm_finalize_256_test_funcs); i++) {
                fail |= test_aes_gcm_finalize_api(
                        gcm_finalize_256_test_funcs[i].gcm_finalize_func_ptr,
                        gcm_finalize_256_test_funcs[i].func_name, BITS_256);
        }

        /* Test AES-GCM pre API */
        const struct test_func gcm_pre_test_funcs[] = {
                { .gcm_pre_func_ptr = isal_aes_gcm_pre_128, "isal_aes_gcm_pre_128" },
                { .gcm_pre_func_ptr = isal_aes_gcm_pre_256, "isal_aes_gcm_pre_256" },
        };

        for (int i = 0; i < DIM(gcm_pre_test_funcs); i++) {
                fail |= test_aes_gcm_pre_api(gcm_pre_test_funcs[i].gcm_pre_func_ptr,
                                             gcm_pre_test_funcs[i].func_name);
        }

        printf(fail ? "Fail\n" : "Pass\n");
#else
        printf("Not Executed\n");
#endif
        return fail;
}
