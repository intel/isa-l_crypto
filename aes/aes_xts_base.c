/**********************************************************************
  Copyright (c) 2026 Institute of Software Chinese Academy of Sciences (ISCAS).

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of ISCAS nor the names of its
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
#include <stdlib.h>
#include <string.h>
#include "aes_base.h"

static int
buffers_partially_overlap(const uint8_t *a, const uint8_t *b, uint64_t len)
{
        uintptr_t au, bu;

        if (a == b || len == 0)
                return 0;

        au = (uintptr_t) a;
        bu = (uintptr_t) b;

        return (au < bu) ? (uint64_t) (bu - au) < len : (uint64_t) (au - bu) < len;
}

static void
xts_crypt_block(const uint8_t *in, uint8_t *out, const uint8_t *keys, const uint8_t *tweak, int nr,
                int decrypt)
{
        uint8_t block[16];
        int j;

        for (j = 0; j < 16; j++)
                block[j] = in[j] ^ tweak[j];

        if (decrypt)
                aes_base_decrypt_block(block, block, keys, nr);
        else
                aes_base_encrypt_block(block, block, keys, nr);

        for (j = 0; j < 16; j++)
                out[j] = block[j] ^ tweak[j];

        aes_base_secure_zero(block, sizeof(block));
}

static void
xts_enc_expanded_key(uint8_t *k2_exp, uint8_t *k1_exp, uint8_t *TW_initial, uint64_t N,
                     const uint8_t *pt, uint8_t *ct, int nr)
{
        uint8_t tweak[16];
        uint64_t full_blocks;
        uint64_t remainder;
        uint64_t main_blocks;
        uint64_t i;
        uint8_t *tmp;

        /*
         * The isa-l XTS API has no error channel. Invalid short inputs and
         * allocation failures below leave the output untouched.
         */
        if (N < 16)
                return;

        if (buffers_partially_overlap(pt, ct, N)) {
                if (N > SIZE_MAX)
                        return;
                tmp = malloc((size_t) N);
                if (tmp == NULL)
                        return;
                memcpy(tmp, pt, (size_t) N);
                xts_enc_expanded_key(k2_exp, k1_exp, TW_initial, N, tmp, ct, nr);
                aes_base_secure_zero(tmp, (size_t) N);
                free(tmp);
                return;
        }

        aes_base_encrypt_block(TW_initial, tweak, k2_exp, nr);
        full_blocks = N / 16;
        remainder = N % 16;
        main_blocks = (remainder > 0) ? full_blocks - 1 : full_blocks;

        for (i = 0; i < main_blocks; i++) {
                xts_crypt_block(pt + i * 16, ct + i * 16, k1_exp, tweak, nr, 0);
                aes_base_xts_mul_alpha(tweak);
        }

        if (remainder > 0) {
                uint8_t tweak_next[16];
                uint8_t cc[16];
                uint8_t stolen[16];
                int j;

                xts_crypt_block(pt + main_blocks * 16, cc, k1_exp, tweak, nr, 0);

                for (j = 0; j < (int) remainder; j++)
                        stolen[j] = pt[(main_blocks + 1) * 16 + j];
                for (j = (int) remainder; j < 16; j++)
                        stolen[j] = cc[j];

                memcpy(ct + (main_blocks + 1) * 16, cc, remainder);

                memcpy(tweak_next, tweak, 16);
                aes_base_xts_mul_alpha(tweak_next);
                xts_crypt_block(stolen, ct + main_blocks * 16, k1_exp, tweak_next, nr, 0);

                aes_base_secure_zero(tweak_next, sizeof(tweak_next));
                aes_base_secure_zero(cc, sizeof(cc));
                aes_base_secure_zero(stolen, sizeof(stolen));
        }

        aes_base_secure_zero(tweak, sizeof(tweak));
}

static void
xts_dec_expanded_key(uint8_t *k2_exp, uint8_t *k1_exp, uint8_t *TW_initial, uint64_t N,
                     const uint8_t *ct, uint8_t *pt, int nr)
{
        uint8_t tweak[16];
        uint64_t full_blocks;
        uint64_t remainder;
        uint64_t main_blocks;
        uint64_t i;
        uint8_t *tmp;

        /*
         * The isa-l XTS API has no error channel. Invalid short inputs and
         * allocation failures below leave the output untouched.
         */
        if (N < 16)
                return;

        if (buffers_partially_overlap(ct, pt, N)) {
                if (N > SIZE_MAX)
                        return;
                tmp = malloc((size_t) N);
                if (tmp == NULL)
                        return;
                memcpy(tmp, ct, (size_t) N);
                xts_dec_expanded_key(k2_exp, k1_exp, TW_initial, N, tmp, pt, nr);
                aes_base_secure_zero(tmp, (size_t) N);
                free(tmp);
                return;
        }

        aes_base_encrypt_block(TW_initial, tweak, k2_exp, nr);
        full_blocks = N / 16;
        remainder = N % 16;
        main_blocks = (remainder > 0) ? full_blocks - 1 : full_blocks;

        for (i = 0; i < main_blocks; i++) {
                xts_crypt_block(ct + i * 16, pt + i * 16, k1_exp, tweak, nr, 1);
                aes_base_xts_mul_alpha(tweak);
        }

        if (remainder > 0) {
                uint8_t tweak_next[16];
                uint8_t pp[16];
                uint8_t cc[16];
                int j;

                memcpy(tweak_next, tweak, 16);
                aes_base_xts_mul_alpha(tweak_next);
                xts_crypt_block(ct + main_blocks * 16, pp, k1_exp, tweak_next, nr, 1);

                for (j = 0; j < (int) remainder; j++)
                        cc[j] = ct[(main_blocks + 1) * 16 + j];
                for (j = (int) remainder; j < 16; j++)
                        cc[j] = pp[j];

                memcpy(pt + (main_blocks + 1) * 16, pp, remainder);

                xts_crypt_block(cc, pt + main_blocks * 16, k1_exp, tweak, nr, 1);

                aes_base_secure_zero(tweak_next, sizeof(tweak_next));
                aes_base_secure_zero(pp, sizeof(pp));
                aes_base_secure_zero(cc, sizeof(cc));
        }

        aes_base_secure_zero(tweak, sizeof(tweak));
}

void
XTS_AES_128_enc_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *pt, uint8_t *ct)
{
        xts_enc_expanded_key(k2, k1, TW_initial, N, pt, ct, 10);
}

void
XTS_AES_128_dec_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *ct, uint8_t *pt)
{
        xts_dec_expanded_key(k2, k1, TW_initial, N, ct, pt, 10);
}

void
XTS_AES_256_enc_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *pt, uint8_t *ct)
{
        xts_enc_expanded_key(k2, k1, TW_initial, N, pt, ct, 14);
}

void
XTS_AES_256_dec_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *ct, uint8_t *pt)
{
        xts_dec_expanded_key(k2, k1, TW_initial, N, ct, pt, 14);
}

void
XTS_AES_128_enc_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                     uint8_t *ct)
{
        uint8_t k1_enc[16 * 11], k1_dec[16 * 11];
        uint8_t k2_enc[16 * 11];

        aes_base_keyexp_128(k1, k1_enc, k1_dec);
        aes_base_keyexp_128_enc(k2, k2_enc);
        xts_enc_expanded_key(k2_enc, k1_enc, TW_initial, N, pt, ct, 10);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k1_dec, sizeof(k1_dec));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_128_dec_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                     uint8_t *pt)
{
        uint8_t k1_enc[16 * 11], k1_dec[16 * 11];
        uint8_t k2_enc[16 * 11];

        aes_base_keyexp_128(k1, k1_enc, k1_dec);
        aes_base_keyexp_128_enc(k2, k2_enc);
        xts_dec_expanded_key(k2_enc, k1_dec, TW_initial, N, ct, pt, 10);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k1_dec, sizeof(k1_dec));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_256_enc_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                     uint8_t *ct)
{
        uint8_t k1_enc[16 * 15], k1_dec[16 * 15];
        uint8_t k2_enc[16 * 15];

        aes_base_keyexp_256(k1, k1_enc, k1_dec);
        aes_base_keyexp_256_enc(k2, k2_enc);
        xts_enc_expanded_key(k2_enc, k1_enc, TW_initial, N, pt, ct, 14);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k1_dec, sizeof(k1_dec));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_256_dec_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                     uint8_t *pt)
{
        uint8_t k1_enc[16 * 15], k1_dec[16 * 15];
        uint8_t k2_enc[16 * 15];

        aes_base_keyexp_256(k1, k1_enc, k1_dec);
        aes_base_keyexp_256_enc(k2, k2_enc);
        xts_dec_expanded_key(k2_enc, k1_dec, TW_initial, N, ct, pt, 14);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k1_dec, sizeof(k1_dec));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}
