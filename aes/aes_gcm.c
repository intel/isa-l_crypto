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

#include <stdlib.h>
#include "isal_crypto_api.h"
#include "aes_gcm.h"
#include "aes_gcm_internal.h"

int
isal_aes_gcm_enc_128(const struct isal_gcm_key_data *key_data,
                     struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                     const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                     const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_128(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                         auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_enc_256(const struct isal_gcm_key_data *key_data,
                     struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                     const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                     const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_256(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                         auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_dec_128(const struct isal_gcm_key_data *key_data,
                     struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                     const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                     const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_128(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                         auth_tag, auth_tag_len);
        return 0;
}

int
isal_aes_gcm_dec_256(const struct isal_gcm_key_data *key_data,
                     struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                     const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                     const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_256(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                         auth_tag, auth_tag_len);
        return 0;
}

int
isal_aes_gcm_init_128(const struct isal_gcm_key_data *key_data,
                      struct isal_gcm_context_data *context_data, const uint8_t *iv,
                      const uint8_t *aad, const uint64_t aad_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_init_128(key_data, context_data, (uint8_t *) iv, aad, aad_len);

        return 0;
}

int
isal_aes_gcm_init_256(const struct isal_gcm_key_data *key_data,
                      struct isal_gcm_context_data *context_data, const uint8_t *iv,
                      const uint8_t *aad, const uint64_t aad_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_init_256(key_data, context_data, (uint8_t *) iv, aad, aad_len);

        return 0;
}

int
isal_aes_gcm_enc_128_update(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *context_data, uint8_t *out,
                            const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_128_update(key_data, context_data, out, (uint8_t *) in, len);

        return 0;
}

int
isal_aes_gcm_enc_256_update(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *context_data, uint8_t *out,
                            const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_256_update(key_data, context_data, out, in, len);

        return 0;
}

int
isal_aes_gcm_dec_128_update(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *context_data, uint8_t *out,
                            const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_128_update(key_data, context_data, out, in, len);

        return 0;
}

int
isal_aes_gcm_dec_256_update(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *context_data, uint8_t *out,
                            const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif
        _aes_gcm_dec_256_update(key_data, context_data, out, in, len);

        return 0;
}

int
isal_aes_gcm_enc_128_finalize(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_128_finalize(key_data, context_data, auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_enc_256_finalize(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_256_finalize(key_data, context_data, auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_dec_128_finalize(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_128_finalize(key_data, context_data, auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_dec_256_finalize(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                              const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_256_finalize(key_data, context_data, auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_pre_128(const void *key, struct isal_gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_pre_128(key, key_data);

        return 0;
}

int
isal_aes_gcm_pre_256(const void *key, struct isal_gcm_key_data *key_data)
{
#ifdef SAFE_PARAM
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_pre_256(key, key_data);

        return 0;
}

int
isal_aes_gcm_enc_128_nt(const struct isal_gcm_key_data *key_data,
                        struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                        const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                        const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_128_nt(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                            auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_enc_256_nt(const struct isal_gcm_key_data *key_data,
                        struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                        const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                        const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_256_nt(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                            auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_dec_128_nt(const struct isal_gcm_key_data *key_data,
                        struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                        const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                        const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_128_nt(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                            auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_dec_256_nt(const struct isal_gcm_key_data *key_data,
                        struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                        const uint64_t len, const uint8_t *iv, const uint8_t *aad,
                        const uint64_t aad_len, uint8_t *auth_tag, const uint64_t auth_tag_len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (out == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (in == NULL && len != 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if (aad == NULL && aad_len > 0)
                return ISAL_CRYPTO_ERR_NULL_AAD;
        if (auth_tag == NULL)
                return ISAL_CRYPTO_ERR_NULL_AUTH;
        if (auth_tag_len != ISAL_GCM_MAX_TAG_LEN && auth_tag_len != 12 && auth_tag_len != 8)
                return ISAL_CRYPTO_ERR_AUTH_TAG_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_256_nt(key_data, context_data, out, in, len, (uint8_t *) iv, aad, aad_len,
                            auth_tag, auth_tag_len);

        return 0;
}

int
isal_aes_gcm_enc_128_update_nt(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *context_data, uint8_t *out,
                               const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_128_update_nt(key_data, context_data, out, in, len);
        return 0;
}

int
isal_aes_gcm_enc_256_update_nt(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *context_data, uint8_t *out,
                               const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_enc_256_update_nt(key_data, context_data, out, in, len);

        return 0;
}

int
isal_aes_gcm_dec_128_update_nt(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *context_data, uint8_t *out,
                               const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_128_update_nt(key_data, context_data, out, in, len);

        return 0;
}

int
isal_aes_gcm_dec_256_update_nt(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *context_data, uint8_t *out,
                               const uint8_t *in, const uint64_t len)
{
#ifdef SAFE_PARAM
        if (key_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (context_data == NULL)
                return ISAL_CRYPTO_ERR_NULL_CTX;
        if (in == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL && len > 0)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len > ISAL_GCM_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _aes_gcm_dec_256_update_nt(key_data, context_data, out, in, len);

        return 0;
}

/*
 * =============================================================================
 * LEGACY / DEPRECATED API
 * =============================================================================
 */

void
aes_gcm_enc_128(const struct isal_gcm_key_data *key_data,
                struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len)
{
        _aes_gcm_enc_128(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                         auth_tag_len);
}

void
aes_gcm_enc_256(const struct isal_gcm_key_data *key_data,
                struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len)
{
        _aes_gcm_enc_256(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                         auth_tag_len);
}

void
aes_gcm_dec_128(const struct isal_gcm_key_data *key_data,
                struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len)
{
        _aes_gcm_dec_128(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                         auth_tag_len);
}

void
aes_gcm_dec_256(const struct isal_gcm_key_data *key_data,
                struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                uint64_t auth_tag_len)
{
        _aes_gcm_dec_256(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                         auth_tag_len);
}

void
aes_gcm_init_128(const struct isal_gcm_key_data *key_data,
                 struct isal_gcm_context_data *context_data, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len)
{
        _aes_gcm_init_128(key_data, context_data, iv, aad, aad_len);
}

void
aes_gcm_init_256(const struct isal_gcm_key_data *key_data,
                 struct isal_gcm_context_data *context_data, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len)
{
        _aes_gcm_init_256(key_data, context_data, iv, aad, aad_len);
}

void
aes_gcm_enc_128_update(const struct isal_gcm_key_data *key_data,
                       struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                       uint64_t len)
{
        _aes_gcm_enc_128_update(key_data, context_data, out, in, len);
}

void
aes_gcm_enc_256_update(const struct isal_gcm_key_data *key_data,
                       struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                       uint64_t len)
{
        _aes_gcm_enc_256_update(key_data, context_data, out, in, len);
}

void
aes_gcm_dec_128_update(const struct isal_gcm_key_data *key_data,
                       struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                       uint64_t len)
{
        _aes_gcm_dec_128_update(key_data, context_data, out, in, len);
}

void
aes_gcm_dec_256_update(const struct isal_gcm_key_data *key_data,
                       struct isal_gcm_context_data *context_data, uint8_t *out, const uint8_t *in,
                       uint64_t len)
{
        _aes_gcm_dec_256_update(key_data, context_data, out, in, len);
}

void
aes_gcm_enc_128_finalize(const struct isal_gcm_key_data *key_data,
                         struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                         uint64_t auth_tag_len)
{
        _aes_gcm_enc_128_finalize(key_data, context_data, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_256_finalize(const struct isal_gcm_key_data *key_data,
                         struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                         uint64_t auth_tag_len)
{
        _aes_gcm_enc_256_finalize(key_data, context_data, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_128_finalize(const struct isal_gcm_key_data *key_data,
                         struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                         uint64_t auth_tag_len)
{
        _aes_gcm_dec_128_finalize(key_data, context_data, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_256_finalize(const struct isal_gcm_key_data *key_data,
                         struct isal_gcm_context_data *context_data, uint8_t *auth_tag,
                         uint64_t auth_tag_len)
{
        _aes_gcm_dec_256_finalize(key_data, context_data, auth_tag, auth_tag_len);
}

/* ---- NT versions ---- */

void
aes_gcm_enc_128_nt(const struct isal_gcm_key_data *key_data,
                   struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                   uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                   uint8_t *auth_tag, uint64_t auth_tag_len)
{
        _aes_gcm_enc_128_nt(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

void
aes_gcm_enc_256_nt(const struct isal_gcm_key_data *key_data,
                   struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                   uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                   uint8_t *auth_tag, uint64_t auth_tag_len)
{
        _aes_gcm_enc_256_nt(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

void
aes_gcm_dec_128_nt(const struct isal_gcm_key_data *key_data,
                   struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                   uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                   uint8_t *auth_tag, uint64_t auth_tag_len)
{
        _aes_gcm_dec_128_nt(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

void
aes_gcm_dec_256_nt(const struct isal_gcm_key_data *key_data,
                   struct isal_gcm_context_data *context_data, uint8_t *out, uint8_t const *in,
                   uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
                   uint8_t *auth_tag, uint64_t auth_tag_len)
{
        _aes_gcm_dec_256_nt(key_data, context_data, out, in, len, iv, aad, aad_len, auth_tag,
                            auth_tag_len);
}

void
aes_gcm_enc_128_update_nt(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *context_data, uint8_t *out,
                          const uint8_t *in, uint64_t len)
{
        _aes_gcm_enc_128_update_nt(key_data, context_data, out, in, len);
}

void
aes_gcm_enc_256_update_nt(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *context_data, uint8_t *out,
                          const uint8_t *in, uint64_t len)
{
        _aes_gcm_enc_256_update_nt(key_data, context_data, out, in, len);
}

void
aes_gcm_dec_128_update_nt(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *context_data, uint8_t *out,
                          const uint8_t *in, uint64_t len)
{
        _aes_gcm_dec_128_update_nt(key_data, context_data, out, in, len);
}

void
aes_gcm_dec_256_update_nt(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *context_data, uint8_t *out,
                          const uint8_t *in, uint64_t len)
{
        _aes_gcm_dec_256_update_nt(key_data, context_data, out, in, len);
}
