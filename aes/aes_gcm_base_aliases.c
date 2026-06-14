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
#include "aes_gcm_internal.h"

extern void
aes_gcm_precomp_128_base(struct isal_gcm_key_data *key_data);
extern void
aes_gcm_precomp_256_base(struct isal_gcm_key_data *key_data);
extern void
aes_gcm_init_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
extern void
aes_gcm_init_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                      uint8_t *iv, uint8_t const *aad, uint64_t aad_len);
extern void
aes_gcm_enc_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
extern void
aes_gcm_enc_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
extern void
aes_gcm_dec_128_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
extern void
aes_gcm_dec_256_update_base(const struct isal_gcm_key_data *key_data,
                            struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                            uint64_t len);
extern void
aes_gcm_enc_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
extern void
aes_gcm_enc_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
extern void
aes_gcm_dec_128_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
extern void
aes_gcm_dec_256_finalize_base(const struct isal_gcm_key_data *key_data,
                              struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                              uint64_t auth_tag_len);
extern void
aes_gcm_enc_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len);
extern void
aes_gcm_enc_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len);
extern void
aes_gcm_dec_128_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len);
extern void
aes_gcm_dec_256_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                     uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                     uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len);
extern void
aes_gcm_enc_128_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len);
extern void
aes_gcm_enc_256_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len);
extern void
aes_gcm_dec_128_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len);
extern void
aes_gcm_dec_256_nt_base(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv,
                        uint8_t const *aad, uint64_t aad_len, uint8_t *auth_tag,
                        uint64_t auth_tag_len);
extern void
aes_gcm_enc_128_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len);
extern void
aes_gcm_enc_256_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len);
extern void
aes_gcm_dec_128_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len);
extern void
aes_gcm_dec_256_update_nt_base(const struct isal_gcm_key_data *key_data,
                               struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                               uint64_t len);

void
_aes_gcm_precomp_128(struct isal_gcm_key_data *key_data)
{
        aes_gcm_precomp_128_base(key_data);
}

void
_aes_gcm_precomp_256(struct isal_gcm_key_data *key_data)
{
        aes_gcm_precomp_256_base(key_data);
}

void
_aes_gcm_init_128(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                  uint8_t *iv, uint8_t const *aad, uint64_t aad_len)
{
        aes_gcm_init_128_base(key_data, ctx, iv, aad, aad_len);
}

void
_aes_gcm_init_256(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                  uint8_t *iv, uint8_t const *aad, uint64_t aad_len)
{
        aes_gcm_init_256_base(key_data, ctx, iv, aad, aad_len);
}

void
_aes_gcm_enc_128_update(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, const uint8_t *in, uint64_t len)
{
        aes_gcm_enc_128_update_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_enc_256_update(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, const uint8_t *in, uint64_t len)
{
        aes_gcm_enc_256_update_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_dec_128_update(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, const uint8_t *in, uint64_t len)
{
        aes_gcm_dec_128_update_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_dec_256_update(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                        uint8_t *out, const uint8_t *in, uint64_t len)
{
        aes_gcm_dec_256_update_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_enc_128_finalize(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                          uint64_t auth_tag_len)
{
        aes_gcm_enc_128_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
_aes_gcm_enc_256_finalize(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                          uint64_t auth_tag_len)
{
        aes_gcm_enc_256_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
_aes_gcm_dec_128_finalize(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                          uint64_t auth_tag_len)
{
        aes_gcm_dec_128_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
_aes_gcm_dec_256_finalize(const struct isal_gcm_key_data *key_data,
                          struct isal_gcm_context_data *ctx, uint8_t *auth_tag,
                          uint64_t auth_tag_len)
{
        aes_gcm_dec_256_finalize_base(key_data, ctx, auth_tag, auth_tag_len);
}

void
_aes_gcm_enc_128(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                 uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_enc_128_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
_aes_gcm_enc_256(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                 uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_enc_256_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
_aes_gcm_dec_128(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                 uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_dec_128_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
_aes_gcm_dec_256(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                 uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                 uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_dec_256_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag, auth_tag_len);
}

void
_aes_gcm_enc_128_nt(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_enc_128_nt_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len);
}

void
_aes_gcm_enc_256_nt(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_enc_256_nt_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len);
}

void
_aes_gcm_dec_128_nt(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_dec_128_nt_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len);
}

void
_aes_gcm_dec_256_nt(const struct isal_gcm_key_data *key_data, struct isal_gcm_context_data *ctx,
                    uint8_t *out, uint8_t const *in, uint64_t len, uint8_t *iv, uint8_t const *aad,
                    uint64_t aad_len, uint8_t *auth_tag, uint64_t auth_tag_len)
{
        aes_gcm_dec_256_nt_base(key_data, ctx, out, in, len, iv, aad, aad_len, auth_tag,
                                auth_tag_len);
}

void
_aes_gcm_enc_128_update_nt(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        aes_gcm_enc_128_update_nt_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_enc_256_update_nt(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        aes_gcm_enc_256_update_nt_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_dec_128_update_nt(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        aes_gcm_dec_128_update_nt_base(key_data, ctx, out, in, len);
}

void
_aes_gcm_dec_256_update_nt(const struct isal_gcm_key_data *key_data,
                           struct isal_gcm_context_data *ctx, uint8_t *out, const uint8_t *in,
                           uint64_t len)
{
        aes_gcm_dec_256_update_nt_base(key_data, ctx, out, in, len);
}
