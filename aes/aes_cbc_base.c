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
#include "aes_base.h"

static int
aes_cbc_enc(void *in, uint8_t *IV, uint8_t *enc_keys, void *out, uint64_t len_bytes, int nr)
{
        uint8_t *inp = (uint8_t *) in;
        uint8_t *outp = (uint8_t *) out;
        uint8_t iv[16];
        uint64_t i;
        int j;

        memcpy(iv, IV, 16);

        for (i = 0; i < len_bytes; i += 16) {
                uint8_t block[16];

                for (j = 0; j < 16; j++)
                        block[j] = inp[i + j] ^ iv[j];
                aes_base_encrypt_block(block, outp + i, enc_keys, nr);
                memcpy(iv, outp + i, 16);
        }

        return 0;
}

static void
aes_cbc_dec(void *in, uint8_t *IV, uint8_t *dec_keys, void *out, uint64_t len_bytes, int nr)
{
        uint8_t *inp = (uint8_t *) in;
        uint8_t *outp = (uint8_t *) out;
        uint8_t prev[16];
        uint64_t i;
        int j;

        memcpy(prev, IV, 16);

        for (i = 0; i < len_bytes; i += 16) {
                uint8_t block[16];
                uint8_t saved_ct[16];

                memcpy(saved_ct, inp + i, 16);
                aes_base_decrypt_block(inp + i, block, dec_keys, nr);
                for (j = 0; j < 16; j++)
                        outp[i + j] = block[j] ^ prev[j];
                memcpy(prev, saved_ct, 16);
        }
}

int
aes_cbc_enc_128_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        return aes_cbc_enc(in, IV, keys, out, len_bytes, 10);
}

int
aes_cbc_enc_192_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        return aes_cbc_enc(in, IV, keys, out, len_bytes, 12);
}

int
aes_cbc_enc_256_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        return aes_cbc_enc(in, IV, keys, out, len_bytes, 14);
}

void
aes_cbc_dec_128_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        aes_cbc_dec(in, IV, keys, out, len_bytes, 10);
}

void
aes_cbc_dec_192_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        aes_cbc_dec(in, IV, keys, out, len_bytes, 12);
}

void
aes_cbc_dec_256_base(void *in, uint8_t *IV, uint8_t *keys, void *out, uint64_t len_bytes)
{
        aes_cbc_dec(in, IV, keys, out, len_bytes, 14);
}
