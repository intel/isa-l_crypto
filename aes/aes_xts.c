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
#include <string.h>
#include "isal_crypto_api.h"
#include "aes_xts.h"
#include "aes_xts_internal.h"

int
isal_aes_xts_enc_128(const uint8_t *k2, const uint8_t *k1, const uint8_t *initial_tweak,
                     const uint64_t len_bytes, const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare keys, before expansion (16 bytes) */
        if (memcmp(k1, k2, 16) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_128_enc((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                         (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_enc_128_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare entire expanded keys (16*11 bytes) */
        if (memcmp(k1, k2, 16 * 11) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_128_enc_expanded_key((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                                      (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_dec_128(const uint8_t *k2, const uint8_t *k1, const uint8_t *initial_tweak,
                     const uint64_t len_bytes, const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare keys, before expansion (16 bytes) */
        if (memcmp(k1, k2, 16) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_128_dec((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                         (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_dec_128_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare entire expanded keys (16*11 bytes) */
        if (memcmp(k1, k2, 16 * 11) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_128_dec_expanded_key((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                                      (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_enc_256(const uint8_t *k2, const uint8_t *k1, const uint8_t *initial_tweak,
                     const uint64_t len_bytes, const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare keys, before expansion (16*2 bytes) */
        if (memcmp(k1, k2, 16 * 2) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_256_enc((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                         (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_enc_256_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare entire expanded keys (16*15 bytes) */
        if (memcmp(k1, k2, 16 * 15) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_256_enc_expanded_key((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                                      (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_dec_256(const uint8_t *k2, const uint8_t *k1, const uint8_t *initial_tweak,
                     const uint64_t len_bytes, const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare keys, before expansion (16*2 bytes) */
        if (memcmp(k1, k2, 16 * 2) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_256_dec((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                         (uint64_t) len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_dec_256_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
#ifdef SAFE_PARAM
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;

        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;

        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;

        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;

        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;
#endif

#ifdef FIPS_MODE
        /* Compare entire expanded keys (16*15 bytes) */
        if (memcmp(k1, k2, 16 * 15) == 0)
                return ISAL_CRYPTO_ERR_XTS_SAME_KEYS;

        if (isal_self_tests())
                return ISAL_CRYPTO_ERR_SELF_TEST;
#endif

        _XTS_AES_256_dec_expanded_key((uint8_t *) k2, (uint8_t *) k1, (uint8_t *) initial_tweak,
                                      (uint64_t) len_bytes, in, out);

        return 0;
}

void
XTS_AES_128_enc(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                uint8_t *ct)
{
        _XTS_AES_128_enc(k2, k1, TW_initial, N, pt, ct);
}

void
XTS_AES_128_enc_expanded_key(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                             const uint8_t *pt, uint8_t *ct)
{
        _XTS_AES_128_enc_expanded_key(k2, k1, TW_initial, N, pt, ct);
}

void
XTS_AES_128_dec(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                uint8_t *pt)
{
        _XTS_AES_128_dec(k2, k1, TW_initial, N, ct, pt);
}

void
XTS_AES_128_dec_expanded_key(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                             const uint8_t *ct, uint8_t *pt)
{
        _XTS_AES_128_dec_expanded_key(k2, k1, TW_initial, N, ct, pt);
}

void
XTS_AES_256_enc(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                uint8_t *ct)
{
        _XTS_AES_256_enc(k2, k1, TW_initial, N, pt, ct);
}

void
XTS_AES_256_enc_expanded_key(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                             const uint8_t *pt, uint8_t *ct)
{
        _XTS_AES_256_enc_expanded_key(k2, k1, TW_initial, N, pt, ct);
}

void
XTS_AES_256_dec(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                uint8_t *pt)
{
        _XTS_AES_256_dec(k2, k1, TW_initial, N, ct, pt);
}

void
XTS_AES_256_dec_expanded_key(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                             const uint8_t *ct, uint8_t *pt)
{
        _XTS_AES_256_dec_expanded_key(k2, k1, TW_initial, N, ct, pt);
}
