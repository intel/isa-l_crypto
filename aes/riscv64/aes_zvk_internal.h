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

#ifndef _AES_ZVK_INTERNAL_H_
#define _AES_ZVK_INTERNAL_H_

#include <stdint.h>

void
aes_keyexp_128_enc_base(const uint8_t *key, uint8_t *exp_key_enc);
void
aes_keyexp_256_enc_base(const uint8_t *key, uint8_t *exp_key_enc);

void
aes_encrypt_block_128_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys);
void
aes_encrypt_block_256_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys);
void
aes_decrypt_block_128_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys);
void
aes_decrypt_block_256_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys);
void
aes_decrypt_block_128_dec_keys_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *dec_keys);
void
aes_decrypt_block_256_dec_keys_zvkned(const uint8_t *in, uint8_t *out, const uint8_t *dec_keys);
void
aes_xts_enc_blocks_128_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks, uint8_t *tweak,
                              const uint8_t *enc_keys);
void
aes_xts_dec_blocks_128_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks, uint8_t *tweak,
                              const uint8_t *enc_keys);
void
aes_xts_dec_blocks_128_dec_keys_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks,
                                       uint8_t *tweak, const uint8_t *dec_keys);
void
aes_xts_enc_blocks_256_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks, uint8_t *tweak,
                              const uint8_t *enc_keys);
void
aes_xts_dec_blocks_256_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks, uint8_t *tweak,
                              const uint8_t *enc_keys);
void
aes_xts_dec_blocks_256_dec_keys_zvkned(const uint8_t *in, uint8_t *out, uint64_t nblocks,
                                       uint8_t *tweak, const uint8_t *dec_keys);

void
aes_cbc_enc_128_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);
void
aes_cbc_enc_192_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);
void
aes_cbc_enc_256_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);
void
aes_cbc_dec_128_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);
void
aes_cbc_dec_192_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);
void
aes_cbc_dec_256_zvkned_impl(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes);

void
aes_gcm_ctr32_crypt_128_zvkned_zvkb(const uint8_t *in, uint8_t *out, uint64_t len, uint8_t *iv,
                                    const uint8_t *keys);
void
aes_gcm_ctr32_crypt_256_zvkned_zvkb(const uint8_t *in, uint8_t *out, uint64_t len, uint8_t *iv,
                                    const uint8_t *keys);

/*
 * ghash_zvkg: ZVKG-accelerated GHASH.
 * htable points to four contiguous 16-byte GF(2^128) elements:
 * H, H^2, H^3 and H^4 as computed by the base GCM precomp.
 */
void
ghash_zvkg(uint8_t *accumulator, const uint8_t *htable, const uint8_t *data, uint64_t nblocks);

#endif /* _AES_ZVK_INTERNAL_H_ */
