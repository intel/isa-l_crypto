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

#ifndef _AES_BASE_H_
#define _AES_BASE_H_

#include <stddef.h>
#include <stdint.h>

void
aes_base_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys, int nr);

void
aes_base_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *dec_keys, int nr);

void
aes_base_keyexp_128(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec);

void
aes_base_keyexp_128_enc(const uint8_t *key, uint8_t *exp_key_enc);

void
aes_base_keyexp_192(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec);

void
aes_base_keyexp_256(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec);

void
aes_base_keyexp_256_enc(const uint8_t *key, uint8_t *exp_key_enc);

void
aes_base_xts_mul_alpha(uint8_t *tweak);

void
aes_base_secure_zero(void *ptr, size_t len);

#endif
