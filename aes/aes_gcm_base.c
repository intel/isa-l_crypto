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
#include <string.h>
#include <aes_gcm.h>
#include "aes_base.h"

static void
gf128_mul(uint8_t *X, const uint8_t *Y)
{
        uint8_t V[16], Z[16];
        int i, j;

        memset(Z, 0, 16);
        memcpy(V, Y, 16);

        for (i = 0; i < 128; i++) {
                if (X[i / 8] & (0x80 >> (i % 8))) {
                        for (j = 0; j < 16; j++)
                                Z[j] ^= V[j];
                }
                {
                        int carry = V[15] & 1;

                        for (j = 15; j > 0; j--)
                                V[j] = (uint8_t) ((V[j] >> 1) | (V[j - 1] << 7));
                        V[0] >>= 1;
                        if (carry)
                                V[0] ^= 0xe1;
                }
        }
        memcpy(X, Z, 16);
}

static void
inc32(uint8_t *counter)
{
        int i;

        for (i = 15; i >= 12; i--) {
                if (++counter[i] != 0)
                        break;
        }
}

static void
gcm_precomp(struct isal_gcm_key_data *key_data, int nr)
{
        uint8_t H[16];
        uint8_t Hn[16];
        uint8_t *hkeys[7] = {
                key_data->shifted_hkey_2, key_data->shifted_hkey_3, key_data->shifted_hkey_4,
                key_data->shifted_hkey_5, key_data->shifted_hkey_6, key_data->shifted_hkey_7,
                key_data->shifted_hkey_8,
        };
        uint8_t *hk_src[8] = {
                key_data->shifted_hkey_1, key_data->shifted_hkey_2, key_data->shifted_hkey_3,
                key_data->shifted_hkey_4, key_data->shifted_hkey_5, key_data->shifted_hkey_6,
                key_data->shifted_hkey_7, key_data->shifted_hkey_8,
        };
        uint8_t *hk_dst[8] = {
                key_data->shifted_hkey_1_k, key_data->shifted_hkey_2_k, key_data->shifted_hkey_3_k,
                key_data->shifted_hkey_4_k, key_data->shifted_hkey_5_k, key_data->shifted_hkey_6_k,
                key_data->shifted_hkey_7_k, key_data->shifted_hkey_8_k,
        };
        int i, j;

        memset(H, 0, 16);
        aes_base_encrypt_block(H, H, key_data->expanded_keys, nr);

        /*
         * Despite the historical field names, this base provider stores
         * plain GHASH powers H, H^2, ... in shifted_hkey_1..8. The scalar base
         * GHASH path only needs shifted_hkey_1; crypto extension providers may use
         * the contiguous higher powers, and the *_k fields are compatibility
         * placeholders for the common key-data layout.
         */
        memcpy(key_data->shifted_hkey_1, H, 16);
        memcpy(Hn, H, 16);
        for (i = 0; i < 7; i++) {
                gf128_mul(Hn, H);
                memcpy(hkeys[i], Hn, 16);
        }

        for (i = 0; i < 8; i++) {
                for (j = 0; j < 8; j++) {
                        uint8_t xor_val = hk_src[i][j] ^ hk_src[i][j + 8];

                        hk_dst[i][j] = xor_val;
                        hk_dst[i][j + 8] = xor_val;
                }
        }
        memset(key_data->shifted_hkey_n_k, 0, sizeof(key_data->shifted_hkey_n_k));
}

void
aes_gcm_precomp_128_base(struct isal_gcm_key_data *key_data)
{
        gcm_precomp(key_data, 10);
}

void
aes_gcm_precomp_256_base(struct isal_gcm_key_data *key_data)
{
        gcm_precomp(key_data, 14);
}

static void
ghash_blocks(uint8_t *hash, const uint8_t *H, const uint8_t *in, uint64_t len)
{
        uint64_t i = 0;
        int j;

        while (i + 16 <= len) {
                for (j = 0; j < 16; j++)
                        hash[j] ^= in[i + j];
                gf128_mul(hash, H);
                i += 16;
        }

        if (i < len) {
                for (j = 0; j < (int) (len - i); j++)
                        hash[j] ^= in[i + j];
                gf128_mul(hash, H);
        }
}

static void
gcm_init(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx, uint8_t *iv,
         uint8_t const *aad, uint64_t aad_len)
{
        memcpy(ctx->orig_IV, iv, ISAL_GCM_IV_LEN);
        ctx->orig_IV[12] = 0x00;
        ctx->orig_IV[13] = 0x00;
        ctx->orig_IV[14] = 0x00;
        ctx->orig_IV[15] = 0x01;

        memcpy(ctx->current_counter, ctx->orig_IV, 16);
        inc32(ctx->current_counter);

        memset(ctx->aad_hash, 0, 16);
        ghash_blocks(ctx->aad_hash, key_data->shifted_hkey_1, aad, aad_len);

        ctx->aad_length = aad_len;
        ctx->in_length = 0;
        ctx->partial_block_length = 0;
        memset(ctx->partial_block_enc_key, 0, 16);
}

void
aes_gcm_init_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len)
{
        gcm_init(key_data, ctx, iv, aad, aad_len);
}

void
aes_gcm_init_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len)
{
        gcm_init(key_data, ctx, iv, aad, aad_len);
}

static uint64_t
gcm_update_hash(uint8_t *hash, const uint8_t *H, const uint8_t *in, uint8_t *out, uint64_t len,
                const uint8_t *enc_block, uint64_t *offset, int decrypt)
{
        uint64_t pos = 0;

        while (*offset < 16 && pos < len) {
                uint8_t ct;

                if (decrypt) {
                        ct = in[pos];
                        out[pos] = in[pos] ^ enc_block[*offset];
                } else {
                        ct = in[pos] ^ enc_block[*offset];
                        out[pos] = ct;
                }
                hash[*offset] ^= ct;
                (*offset)++;
                pos++;
        }
        if (*offset == 16) {
                gf128_mul(hash, H);
                *offset = 0;
        }

        return pos;
}

static void
gcm_update(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
           uint8_t *out, const uint8_t *in, uint64_t len, int nr, int decrypt)
{
        const uint8_t *H = key_data->shifted_hkey_1;
        uint64_t offset = ctx->partial_block_length;
        uint64_t pos = 0;
        int j;

        if (offset > 0)
                pos += gcm_update_hash(ctx->aad_hash, H, in, out, len, ctx->partial_block_enc_key,
                                       &offset, decrypt);

        while (pos + 16 <= len) {
                uint8_t enc_block[16];

                aes_base_encrypt_block(ctx->current_counter, enc_block, key_data->expanded_keys,
                                       nr);
                inc32(ctx->current_counter);

                for (j = 0; j < 16; j++) {
                        uint8_t ct;

                        if (decrypt) {
                                ct = in[pos + j];
                                out[pos + j] = in[pos + j] ^ enc_block[j];
                        } else {
                                ct = in[pos + j] ^ enc_block[j];
                                out[pos + j] = ct;
                        }
                        ctx->aad_hash[j] ^= ct;
                }
                gf128_mul(ctx->aad_hash, H);
                pos += 16;
        }

        if (pos < len) {
                aes_base_encrypt_block(ctx->current_counter, ctx->partial_block_enc_key,
                                       key_data->expanded_keys, nr);
                inc32(ctx->current_counter);
                offset = 0;
                gcm_update_hash(ctx->aad_hash, H, in + pos, out + pos, len - pos,
                                ctx->partial_block_enc_key, &offset, decrypt);
        }

        ctx->partial_block_length = offset;
        ctx->in_length += len;
}

void
aes_gcm_enc_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{
        gcm_update(key_data, ctx, out, in, len, 10, 0);
}

void
aes_gcm_enc_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{
        gcm_update(key_data, ctx, out, in, len, 14, 0);
}

void
aes_gcm_dec_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{
        gcm_update(key_data, ctx, out, in, len, 10, 1);
}

void
aes_gcm_dec_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len)
{
        gcm_update(key_data, ctx, out, in, len, 14, 1);
}

static void
gcm_finalize(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
             uint8_t *auth_tag, uint64_t auth_tag_len, int nr)
{
        uint8_t len_block[16];
        uint8_t enc_j0[16];
        uint8_t tag[ISAL_GCM_MAX_TAG_LEN];
        uint64_t aad_bits = ctx->aad_length * 8;
        uint64_t cipher_bits = ctx->in_length * 8;
        uint64_t copy_len;
        int i;

        if (ctx->partial_block_length > 0)
                gf128_mul(ctx->aad_hash, key_data->shifted_hkey_1);

        for (i = 0; i < 8; i++) {
                len_block[i] = (uint8_t) (aad_bits >> (56 - 8 * i));
                len_block[8 + i] = (uint8_t) (cipher_bits >> (56 - 8 * i));
        }

        for (i = 0; i < 16; i++)
                ctx->aad_hash[i] ^= len_block[i];
        gf128_mul(ctx->aad_hash, key_data->shifted_hkey_1);

        aes_base_encrypt_block(ctx->orig_IV, enc_j0, key_data->expanded_keys, nr);
        for (i = 0; i < 16; i++)
                tag[i] = ctx->aad_hash[i] ^ enc_j0[i];

        copy_len = auth_tag_len < ISAL_GCM_MAX_TAG_LEN ? auth_tag_len : ISAL_GCM_MAX_TAG_LEN;
        memcpy(auth_tag, tag, copy_len);
}

void
aes_gcm_enc_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len)
{
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, 10);
}

void
aes_gcm_enc_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len)
{
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, 14);
}

void
aes_gcm_dec_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len)
{
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, 10);
}

void
aes_gcm_dec_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len)
{
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, 14);
}

static void
gcm_enc(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx, uint8_t *out,
        uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
        uint8_t *auth_tag, uint64_t auth_tag_len, int nr)
{
        gcm_init(key_data, ctx, iv, aad, aad_len);
        gcm_update(key_data, ctx, out, in, len, nr, 0);
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, nr);
}

static void
gcm_dec(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx, uint8_t *out,
        uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad, uint64_t aad_len,
        uint8_t *auth_tag, uint64_t auth_tag_len, int nr)
{
        gcm_init(key_data, ctx, iv, aad, aad_len);
        gcm_update(key_data, ctx, out, in, len, nr, 1);
        gcm_finalize(key_data, ctx, auth_tag, auth_tag_len, nr);
}

void
aes_gcm_enc_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        gcm_enc(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len, 10);
}

void
aes_gcm_enc_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        gcm_enc(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len, 14);
}

void
aes_gcm_dec_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        gcm_dec(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len, 10);
}

void
aes_gcm_dec_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        gcm_dec(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len, 14);
}

void
aes_gcm_enc_128_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len)
{
        aes_gcm_enc_128_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_256_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len)
{
        aes_gcm_enc_256_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_128_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len)
{
        aes_gcm_dec_128_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_256_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len)
{
        aes_gcm_dec_256_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_128_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len)
{
        aes_gcm_enc_128_update_base(key_data, ctx, out, in, len);
}

void
aes_gcm_enc_256_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len)
{
        aes_gcm_enc_256_update_base(key_data, ctx, out, in, len);
}

void
aes_gcm_dec_128_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len)
{
        aes_gcm_dec_128_update_base(key_data, ctx, out, in, len);
}

void
aes_gcm_dec_256_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len)
{
        aes_gcm_dec_256_update_base(key_data, ctx, out, in, len);
}
