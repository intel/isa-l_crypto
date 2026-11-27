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

/*
 * Portable fallback provider. This implementation uses data-dependent
 * S-box table lookups and GF branches, so it is not hardened against
 * cache-timing side channels.
 */

static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16
};

static const uint8_t inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d
};

static const uint8_t rcon[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t
xtime(uint8_t x)
{
        return (uint8_t) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t
gf_mul(uint8_t a, uint8_t b)
{
        uint8_t r = 0;
        uint8_t t = a;
        int i;

        for (i = 0; i < 8; i++) {
                if (b & 1)
                        r ^= t;
                t = xtime(t);
                b >>= 1;
        }

        return r;
}

static void
inv_mix_columns_key(const uint8_t *in, uint8_t *out)
{
        int i;

        for (i = 0; i < 4; i++) {
                uint8_t a0 = in[4 * i + 0];
                uint8_t a1 = in[4 * i + 1];
                uint8_t a2 = in[4 * i + 2];
                uint8_t a3 = in[4 * i + 3];

                out[4 * i + 0] =
                        gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
                out[4 * i + 1] =
                        gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
                out[4 * i + 2] =
                        gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
                out[4 * i + 3] =
                        gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
        }
}

static uint32_t
sub_word(uint32_t w)
{
        return ((uint32_t) sbox[(w >> 0) & 0xff] << 0) | ((uint32_t) sbox[(w >> 8) & 0xff] << 8) |
               ((uint32_t) sbox[(w >> 16) & 0xff] << 16) |
               ((uint32_t) sbox[(w >> 24) & 0xff] << 24);
}

static uint32_t
rot_word(uint32_t w)
{
        return (w >> 8) | (w << 24);
}

static uint32_t
load_u32_le(const uint8_t *p)
{
        return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
               ((uint32_t) p[3] << 24);
}

static void
store_u32_le(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t) (v >> 0);
        p[1] = (uint8_t) (v >> 8);
        p[2] = (uint8_t) (v >> 16);
        p[3] = (uint8_t) (v >> 24);
}

static void
mix_columns(uint8_t *state)
{
        int i;

        for (i = 0; i < 4; i++) {
                uint8_t a = state[4 * i + 0];
                uint8_t b = state[4 * i + 1];
                uint8_t c = state[4 * i + 2];
                uint8_t d = state[4 * i + 3];
                uint8_t e = a ^ b ^ c ^ d;

                state[4 * i + 0] ^= e ^ xtime(a ^ b);
                state[4 * i + 1] ^= e ^ xtime(b ^ c);
                state[4 * i + 2] ^= e ^ xtime(c ^ d);
                state[4 * i + 3] ^= e ^ xtime(d ^ a);
        }
}

static void
inv_mix_columns(uint8_t *state)
{
        int i;

        for (i = 0; i < 4; i++) {
                uint8_t a0 = state[4 * i + 0];
                uint8_t a1 = state[4 * i + 1];
                uint8_t a2 = state[4 * i + 2];
                uint8_t a3 = state[4 * i + 3];
                uint8_t u = xtime(xtime(a0 ^ a2));
                uint8_t v = xtime(xtime(a1 ^ a3));
                uint8_t e;

                a0 ^= u;
                a1 ^= v;
                a2 ^= u;
                a3 ^= v;
                e = a0 ^ a1 ^ a2 ^ a3;
                state[4 * i + 0] = a0 ^ e ^ xtime(a0 ^ a1);
                state[4 * i + 1] = a1 ^ e ^ xtime(a1 ^ a2);
                state[4 * i + 2] = a2 ^ e ^ xtime(a2 ^ a3);
                state[4 * i + 3] = a3 ^ e ^ xtime(a3 ^ a0);
        }
}

void
aes_base_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *enc_keys, int nr)
{
        uint8_t state[16];
        int i, round;

        for (i = 0; i < 16; i++)
                state[i] = in[i] ^ enc_keys[i];

        for (round = 1; round < nr; round++) {
                uint8_t tmp[16];

                for (i = 0; i < 16; i++)
                        tmp[i] = sbox[state[i]];

                state[0] = tmp[0];
                state[1] = tmp[5];
                state[2] = tmp[10];
                state[3] = tmp[15];
                state[4] = tmp[4];
                state[5] = tmp[9];
                state[6] = tmp[14];
                state[7] = tmp[3];
                state[8] = tmp[8];
                state[9] = tmp[13];
                state[10] = tmp[2];
                state[11] = tmp[7];
                state[12] = tmp[12];
                state[13] = tmp[1];
                state[14] = tmp[6];
                state[15] = tmp[11];

                mix_columns(state);
                for (i = 0; i < 16; i++)
                        state[i] ^= enc_keys[round * 16 + i];
        }

        {
                uint8_t tmp[16];

                for (i = 0; i < 16; i++)
                        tmp[i] = sbox[state[i]];

                state[0] = tmp[0];
                state[1] = tmp[5];
                state[2] = tmp[10];
                state[3] = tmp[15];
                state[4] = tmp[4];
                state[5] = tmp[9];
                state[6] = tmp[14];
                state[7] = tmp[3];
                state[8] = tmp[8];
                state[9] = tmp[13];
                state[10] = tmp[2];
                state[11] = tmp[7];
                state[12] = tmp[12];
                state[13] = tmp[1];
                state[14] = tmp[6];
                state[15] = tmp[11];
        }

        for (i = 0; i < 16; i++)
                out[i] = state[i] ^ enc_keys[nr * 16 + i];
}

void
aes_base_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *dec_keys, int nr)
{
        uint8_t state[16];
        int i, round;

        for (i = 0; i < 16; i++)
                state[i] = in[i] ^ dec_keys[i];

        for (round = 1; round < nr; round++) {
                uint8_t tmp[16];

                tmp[0] = state[0];
                tmp[5] = state[1];
                tmp[10] = state[2];
                tmp[15] = state[3];
                tmp[4] = state[4];
                tmp[9] = state[5];
                tmp[14] = state[6];
                tmp[3] = state[7];
                tmp[8] = state[8];
                tmp[13] = state[9];
                tmp[2] = state[10];
                tmp[7] = state[11];
                tmp[12] = state[12];
                tmp[1] = state[13];
                tmp[6] = state[14];
                tmp[11] = state[15];

                for (i = 0; i < 16; i++)
                        state[i] = inv_sbox[tmp[i]];

                inv_mix_columns(state);
                for (i = 0; i < 16; i++)
                        state[i] ^= dec_keys[round * 16 + i];
        }

        {
                uint8_t tmp[16];

                tmp[0] = state[0];
                tmp[5] = state[1];
                tmp[10] = state[2];
                tmp[15] = state[3];
                tmp[4] = state[4];
                tmp[9] = state[5];
                tmp[14] = state[6];
                tmp[3] = state[7];
                tmp[8] = state[8];
                tmp[13] = state[9];
                tmp[2] = state[10];
                tmp[7] = state[11];
                tmp[12] = state[12];
                tmp[1] = state[13];
                tmp[6] = state[14];
                tmp[11] = state[15];

                for (i = 0; i < 16; i++)
                        out[i] = inv_sbox[tmp[i]] ^ dec_keys[nr * 16 + i];
        }
}

static void
store_dec_keys(const uint8_t *enc_keys, uint8_t *dec_keys, int nr)
{
        int i;

        memcpy(dec_keys, enc_keys + nr * 16, 16);
        for (i = 1; i < nr; i++)
                inv_mix_columns_key(enc_keys + (nr - i) * 16, dec_keys + i * 16);
        memcpy(dec_keys + nr * 16, enc_keys, 16);
}

static void
keyexp_generic(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec, int nk, int nr)
{
        uint32_t w[60];
        int words = 4 * (nr + 1);
        int i;

        for (i = 0; i < nk; i++)
                w[i] = load_u32_le(key + 4 * i);

        for (i = nk; i < words; i++) {
                uint32_t temp = w[i - 1];

                if ((i % nk) == 0)
                        temp = sub_word(rot_word(temp)) ^ ((uint32_t) rcon[i / nk]);
                else if (nk > 6 && (i % nk) == 4)
                        temp = sub_word(temp);
                w[i] = w[i - nk] ^ temp;
        }

        for (i = 0; i < words; i++)
                store_u32_le(exp_key_enc + 4 * i, w[i]);

        if (exp_key_dec != NULL)
                store_dec_keys(exp_key_enc, exp_key_dec, nr);
}

void
aes_base_keyexp_128(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
        keyexp_generic(key, exp_key_enc, exp_key_dec, 4, 10);
}

void
aes_base_keyexp_128_enc(const uint8_t *key, uint8_t *exp_key_enc)
{
        keyexp_generic(key, exp_key_enc, NULL, 4, 10);
}

void
aes_base_keyexp_192(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
        keyexp_generic(key, exp_key_enc, exp_key_dec, 6, 12);
}

void
aes_base_keyexp_256(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
        keyexp_generic(key, exp_key_enc, exp_key_dec, 8, 14);
}

void
aes_base_keyexp_256_enc(const uint8_t *key, uint8_t *exp_key_enc)
{
        keyexp_generic(key, exp_key_enc, NULL, 8, 14);
}

void
aes_base_xts_mul_alpha(uint8_t *tweak)
{
        int i;
        uint8_t carry = 0;
        uint8_t next_carry;

        for (i = 0; i < 16; i++) {
                next_carry = tweak[i] >> 7;
                tweak[i] = (uint8_t) ((tweak[i] << 1) | carry);
                carry = next_carry;
        }
        if (carry)
                tweak[0] ^= 0x87;
}

void
aes_base_secure_zero(void *ptr, size_t len)
{
#if defined(HAVE_EXPLICIT_BZERO) && HAVE_EXPLICIT_BZERO
        explicit_bzero(ptr, len);
#else
        volatile uint8_t *p = (volatile uint8_t *) ptr;

        while (len-- != 0)
                *p++ = 0;
#endif
}
