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
#include "aes_zvk_internal.h"

#if HAVE_RISCV_ZVK

void
XTS_AES_128_enc_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                     uint8_t *ct);
void
XTS_AES_128_dec_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                     uint8_t *pt);
void
XTS_AES_128_enc_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *pt, uint8_t *ct);
void
XTS_AES_128_dec_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *ct, uint8_t *pt);
void
XTS_AES_256_enc_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                     uint8_t *ct);
void
XTS_AES_256_dec_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                     uint8_t *pt);
void
XTS_AES_256_enc_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *pt, uint8_t *ct);
void
XTS_AES_256_dec_expanded_key_base(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                  const uint8_t *ct, uint8_t *pt);

typedef void (*aes_block_fn)(const uint8_t *in, uint8_t *out, const uint8_t *keys);
typedef void (*xts_blocks_fn)(const uint8_t *in, uint8_t *out, uint64_t nblocks, uint8_t *tweak,
                              const uint8_t *keys);

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
xts_enc_expanded_key_zvkned(uint8_t *k2_exp, uint8_t *k1_exp, uint8_t *TW_initial, uint64_t N,
                            const uint8_t *pt, uint8_t *ct, aes_block_fn enc_block,
                            xts_blocks_fn enc_blocks)
{
        uint8_t tweak[16];
        uint8_t block[16];
        uint8_t stolen[16];
        uint8_t last_ct[16];
        uint8_t *tmp;
        uint64_t full_blocks, remainder, main_blocks, i;
        int j;

        /*
         * The isa-l XTS API has no error channel. Invalid short inputs and
         * allocation failures below leave the output untouched.
         */
        if (N < 16) {
                return;
        }

        if (buffers_partially_overlap(pt, ct, N)) {
                if (N > SIZE_MAX)
                        return;
                tmp = malloc((size_t) N);
                if (tmp == NULL)
                        return;
                memcpy(tmp, pt, (size_t) N);
                xts_enc_expanded_key_zvkned(k2_exp, k1_exp, TW_initial, N, tmp, ct, enc_block,
                                            enc_blocks);
                aes_base_secure_zero(tmp, (size_t) N);
                free(tmp);
                return;
        }

        enc_block(TW_initial, tweak, k2_exp);

        full_blocks = N / 16;
        remainder = N % 16;
        main_blocks = (remainder > 0) ? full_blocks - 1 : full_blocks;

        if (enc_blocks != NULL && main_blocks > 0) {
                enc_blocks(pt, ct, main_blocks, tweak, k1_exp);
        } else {
                for (i = 0; i < main_blocks; i++) {
                        for (j = 0; j < 16; j++)
                                block[j] = pt[i * 16 + j] ^ tweak[j];
                        enc_block(block, block, k1_exp);
                        for (j = 0; j < 16; j++)
                                ct[i * 16 + j] = block[j] ^ tweak[j];
                        aes_base_xts_mul_alpha(tweak);
                }
        }

        if (remainder > 0) {
                for (j = 0; j < 16; j++)
                        block[j] = pt[main_blocks * 16 + j] ^ tweak[j];
                enc_block(block, last_ct, k1_exp);
                for (j = 0; j < 16; j++)
                        last_ct[j] ^= tweak[j];

                for (j = 0; j < (int) remainder; j++)
                        stolen[j] = pt[(main_blocks + 1) * 16 + j];
                for (j = (int) remainder; j < 16; j++)
                        stolen[j] = last_ct[j];

                memcpy(ct + (main_blocks + 1) * 16, last_ct, remainder);

                aes_base_xts_mul_alpha(tweak);
                for (j = 0; j < 16; j++)
                        block[j] = stolen[j] ^ tweak[j];
                enc_block(block, block, k1_exp);
                for (j = 0; j < 16; j++)
                        ct[main_blocks * 16 + j] = block[j] ^ tweak[j];
        }

        aes_base_secure_zero(tweak, sizeof(tweak));
        aes_base_secure_zero(block, sizeof(block));
        aes_base_secure_zero(stolen, sizeof(stolen));
        aes_base_secure_zero(last_ct, sizeof(last_ct));
}

static void
xts_dec_expanded_key_zvkned(uint8_t *k2_exp, uint8_t *k1_exp, uint8_t *TW_initial, uint64_t N,
                            const uint8_t *ct, uint8_t *pt, aes_block_fn enc_block,
                            aes_block_fn dec_block, xts_blocks_fn dec_blocks)
{
        uint8_t tweak[16];
        uint8_t tweak_next[16];
        uint8_t block[16];
        uint8_t stolen[16];
        uint8_t last_pt[16];
        uint8_t *tmp;
        uint64_t full_blocks, remainder, main_blocks, i;
        int j;

        /*
         * The isa-l XTS API has no error channel. Invalid short inputs and
         * allocation failures below leave the output untouched.
         */
        if (N < 16) {
                return;
        }

        if (buffers_partially_overlap(ct, pt, N)) {
                if (N > SIZE_MAX)
                        return;
                tmp = malloc((size_t) N);
                if (tmp == NULL)
                        return;
                memcpy(tmp, ct, (size_t) N);
                xts_dec_expanded_key_zvkned(k2_exp, k1_exp, TW_initial, N, tmp, pt, enc_block,
                                            dec_block, dec_blocks);
                aes_base_secure_zero(tmp, (size_t) N);
                free(tmp);
                return;
        }

        enc_block(TW_initial, tweak, k2_exp);

        full_blocks = N / 16;
        remainder = N % 16;
        main_blocks = (remainder > 0) ? full_blocks - 1 : full_blocks;

        if (dec_blocks != NULL && main_blocks > 0) {
                dec_blocks(ct, pt, main_blocks, tweak, k1_exp);
        } else {
                for (i = 0; i < main_blocks; i++) {
                        for (j = 0; j < 16; j++)
                                block[j] = ct[i * 16 + j] ^ tweak[j];
                        dec_block(block, block, k1_exp);
                        for (j = 0; j < 16; j++)
                                pt[i * 16 + j] = block[j] ^ tweak[j];
                        aes_base_xts_mul_alpha(tweak);
                }
        }

        if (remainder > 0) {
                memcpy(tweak_next, tweak, 16);
                aes_base_xts_mul_alpha(tweak_next);

                for (j = 0; j < 16; j++)
                        block[j] = ct[main_blocks * 16 + j] ^ tweak_next[j];
                dec_block(block, last_pt, k1_exp);
                for (j = 0; j < 16; j++)
                        last_pt[j] ^= tweak_next[j];

                for (j = 0; j < (int) remainder; j++)
                        stolen[j] = ct[(main_blocks + 1) * 16 + j];
                for (j = (int) remainder; j < 16; j++)
                        stolen[j] = last_pt[j];

                memcpy(pt + (main_blocks + 1) * 16, last_pt, remainder);

                for (j = 0; j < 16; j++)
                        block[j] = stolen[j] ^ tweak[j];
                dec_block(block, block, k1_exp);
                for (j = 0; j < 16; j++)
                        pt[main_blocks * 16 + j] = block[j] ^ tweak[j];
        }

        aes_base_secure_zero(tweak, sizeof(tweak));
        aes_base_secure_zero(tweak_next, sizeof(tweak_next));
        aes_base_secure_zero(block, sizeof(block));
        aes_base_secure_zero(stolen, sizeof(stolen));
        aes_base_secure_zero(last_pt, sizeof(last_pt));
}

void
XTS_AES_128_enc_expanded_key_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                    const uint8_t *pt, uint8_t *ct)
{
        xts_enc_expanded_key_zvkned(k2, k1, TW_initial, N, pt, ct, aes_encrypt_block_128_zvkned,
                                    aes_xts_enc_blocks_128_zvkned);
}

void
XTS_AES_128_dec_expanded_key_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                    const uint8_t *ct, uint8_t *pt)
{
        xts_dec_expanded_key_zvkned(k2, k1, TW_initial, N, ct, pt, aes_encrypt_block_128_zvkned,
                                    aes_decrypt_block_128_dec_keys_zvkned,
                                    aes_xts_dec_blocks_128_dec_keys_zvkned);
}

void
XTS_AES_256_enc_expanded_key_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                    const uint8_t *pt, uint8_t *ct)
{
        xts_enc_expanded_key_zvkned(k2, k1, TW_initial, N, pt, ct, aes_encrypt_block_256_zvkned,
                                    aes_xts_enc_blocks_256_zvkned);
}

void
XTS_AES_256_dec_expanded_key_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N,
                                    const uint8_t *ct, uint8_t *pt)
{
        xts_dec_expanded_key_zvkned(k2, k1, TW_initial, N, ct, pt, aes_encrypt_block_256_zvkned,
                                    aes_decrypt_block_256_dec_keys_zvkned,
                                    aes_xts_dec_blocks_256_dec_keys_zvkned);
}

void
XTS_AES_128_enc_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                       uint8_t *ct)
{
        uint8_t k1_enc[16 * 11];
        uint8_t k2_enc[16 * 11];

        aes_keyexp_128_enc_base(k1, k1_enc);
        aes_keyexp_128_enc_base(k2, k2_enc);
        xts_enc_expanded_key_zvkned(k2_enc, k1_enc, TW_initial, N, pt, ct,
                                    aes_encrypt_block_128_zvkned, aes_xts_enc_blocks_128_zvkned);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_128_dec_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                       uint8_t *pt)
{
        uint8_t k1_enc[16 * 11];
        uint8_t k2_enc[16 * 11];

        aes_keyexp_128_enc_base(k1, k1_enc);
        aes_keyexp_128_enc_base(k2, k2_enc);
        xts_dec_expanded_key_zvkned(k2_enc, k1_enc, TW_initial, N, ct, pt,
                                    aes_encrypt_block_128_zvkned, aes_decrypt_block_128_zvkned,
                                    aes_xts_dec_blocks_128_zvkned);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_256_enc_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *pt,
                       uint8_t *ct)
{
        uint8_t k1_enc[16 * 15];
        uint8_t k2_enc[16 * 15];

        aes_keyexp_256_enc_base(k1, k1_enc);
        aes_keyexp_256_enc_base(k2, k2_enc);
        xts_enc_expanded_key_zvkned(k2_enc, k1_enc, TW_initial, N, pt, ct,
                                    aes_encrypt_block_256_zvkned, aes_xts_enc_blocks_256_zvkned);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

void
XTS_AES_256_dec_zvkned(uint8_t *k2, uint8_t *k1, uint8_t *TW_initial, uint64_t N, const uint8_t *ct,
                       uint8_t *pt)
{
        uint8_t k1_enc[16 * 15];
        uint8_t k2_enc[16 * 15];

        aes_keyexp_256_enc_base(k1, k1_enc);
        aes_keyexp_256_enc_base(k2, k2_enc);
        xts_dec_expanded_key_zvkned(k2_enc, k1_enc, TW_initial, N, ct, pt,
                                    aes_encrypt_block_256_zvkned, aes_decrypt_block_256_zvkned,
                                    aes_xts_dec_blocks_256_zvkned);
        aes_base_secure_zero(k1_enc, sizeof(k1_enc));
        aes_base_secure_zero(k2_enc, sizeof(k2_enc));
}

#endif
