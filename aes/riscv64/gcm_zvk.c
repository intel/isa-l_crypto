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

#include "aes_gcm.h"
#include "aes_zvk_internal.h"

#if HAVE_RISCV_ZVK

void
aes_gcm_init_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aes_gcm_init_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
void
aes_gcm_enc_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
void
aes_gcm_enc_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
void
aes_gcm_dec_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
void
aes_gcm_dec_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
void
aes_gcm_enc_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
void
aes_gcm_enc_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
void
aes_gcm_dec_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
void
aes_gcm_dec_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);

typedef void (*gcm_ctr_fn)(const uint8_t *in, uint8_t *out, uint64_t len, uint8_t *iv,
                           const uint8_t *keys);
typedef void (*gcm_update_base_fn)(const struct isal_gcm_key_data *key_data,
                                   struct isal_gcm_context_data *ctx, uint8_t *out,
                                   const uint8_t *in, uint64_t len);

static void
gcm_update_enc_zvk_common(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                          uint64_t len, gcm_ctr_fn ctr_fn, gcm_update_base_fn base_fn)
{
        uint64_t full_len;
        uint64_t rem_len;

        if (ctx->partial_block_length != 0) {
                uint64_t drain = 16 - ctx->partial_block_length;
                if (len <= drain) {
                        base_fn(key_data, ctx, out, in, len);
                        return;
                }
                base_fn(key_data, ctx, out, in, drain);
                out += drain;
                in += drain;
                len -= drain;
        }

        if (len < 16) {
                base_fn(key_data, ctx, out, in, len);
                return;
        }

        full_len = len & ~UINT64_C(15);
        rem_len = len - full_len;

        if (full_len != 0) {
                ctr_fn(in, out, full_len, ctx->current_counter, key_data->expanded_keys);
                ghash_zvkg(ctx->aad_hash, key_data->shifted_hkey_1, out, full_len / 16);
                ctx->in_length += full_len;
        }

        if (rem_len != 0) {
                base_fn(key_data, ctx, out + full_len, in + full_len, rem_len);
        }
}

static void
gcm_update_dec_zvk_common(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                          uint64_t len, gcm_ctr_fn ctr_fn, gcm_update_base_fn base_fn)
{
        uint64_t full_len;
        uint64_t rem_len;

        if (ctx->partial_block_length != 0) {
                uint64_t drain = 16 - ctx->partial_block_length;
                if (len <= drain) {
                        base_fn(key_data, ctx, out, in, len);
                        return;
                }
                base_fn(key_data, ctx, out, in, drain);
                out += drain;
                in += drain;
                len -= drain;
        }

        if (len < 16) {
                base_fn(key_data, ctx, out, in, len);
                return;
        }

        full_len = len & ~UINT64_C(15);
        rem_len = len - full_len;

        if (full_len != 0) {
                ghash_zvkg(ctx->aad_hash, key_data->shifted_hkey_1, in, full_len / 16);
                ctr_fn(in, out, full_len, ctx->current_counter, key_data->expanded_keys);
                ctx->in_length += full_len;
        }

        if (rem_len != 0) {
                base_fn(key_data, ctx, out + full_len, in + full_len, rem_len);
        }
}

void
aes_gcm_enc_128_update_zvk(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        gcm_update_enc_zvk_common(key_data, ctx, out, in, len, aes_gcm_ctr32_crypt_128_zvkned_zvkb,
                                  aes_gcm_enc_128_update_base);
}

void
aes_gcm_enc_256_update_zvk(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        gcm_update_enc_zvk_common(key_data, ctx, out, in, len, aes_gcm_ctr32_crypt_256_zvkned_zvkb,
                                  aes_gcm_enc_256_update_base);
}

void
aes_gcm_dec_128_update_zvk(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        gcm_update_dec_zvk_common(key_data, ctx, out, in, len, aes_gcm_ctr32_crypt_128_zvkned_zvkb,
                                  aes_gcm_dec_128_update_base);
}

void
aes_gcm_dec_256_update_zvk(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        gcm_update_dec_zvk_common(key_data, ctx, out, in, len, aes_gcm_ctr32_crypt_256_zvkned_zvkb,
                                  aes_gcm_dec_256_update_base);
}

void
aes_gcm_enc_128_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_init_128_base(key_data, ctx, iv, aad, aad_len);
        aes_gcm_enc_128_update_zvk(key_data, ctx, out, in, len);
        aes_gcm_enc_128_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_256_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_init_256_base(key_data, ctx, iv, aad, aad_len);
        aes_gcm_enc_256_update_zvk(key_data, ctx, out, in, len);
        aes_gcm_enc_256_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_128_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_init_128_base(key_data, ctx, iv, aad, aad_len);
        aes_gcm_dec_128_update_zvk(key_data, ctx, out, in, len);
        aes_gcm_dec_128_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_256_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_init_256_base(key_data, ctx, iv, aad, aad_len);
        aes_gcm_dec_256_update_zvk(key_data, ctx, out, in, len);
        aes_gcm_dec_256_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_128_nt_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                       uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                       uint64_t auth_tag_len)
{
        aes_gcm_enc_128_zvk(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_256_nt_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                       uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                       uint64_t auth_tag_len)
{
        aes_gcm_enc_256_zvk(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_128_nt_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                       uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                       uint64_t auth_tag_len)
{
        aes_gcm_dec_128_zvk(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_dec_256_nt_zvk(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                       uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                       uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                       uint64_t auth_tag_len)
{
        aes_gcm_dec_256_zvk(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
aes_gcm_enc_128_update_nt_zvk(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                              uint64_t len)
{
        aes_gcm_enc_128_update_zvk(key_data, ctx, out, in, len);
}

void
aes_gcm_enc_256_update_nt_zvk(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                              uint64_t len)
{
        aes_gcm_enc_256_update_zvk(key_data, ctx, out, in, len);
}

void
aes_gcm_dec_128_update_nt_zvk(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                              uint64_t len)
{
        aes_gcm_dec_128_update_zvk(key_data, ctx, out, in, len);
}

void
aes_gcm_dec_256_update_nt_zvk(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                              uint64_t len)
{
        aes_gcm_dec_256_update_zvk(key_data, ctx, out, in, len);
}

#endif
