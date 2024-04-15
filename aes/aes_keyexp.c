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
#include "isal_crypto_api.h"
#include "aes_keyexp.h"

int
isal_aes_keyexp_128(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
#ifdef SAFE_PARAM
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (exp_key_enc == NULL || exp_key_dec == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
#endif
        aes_keyexp_128(key, exp_key_enc, exp_key_dec);

        return 0;
}

int
isal_aes_keyexp_192(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
#ifdef SAFE_PARAM
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (exp_key_enc == NULL || exp_key_dec == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
#endif
        aes_keyexp_192(key, exp_key_enc, exp_key_dec);

        return 0;
}

int
isal_aes_keyexp_256(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
#ifdef SAFE_PARAM
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (exp_key_enc == NULL || exp_key_dec == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
#endif
        aes_keyexp_256(key, exp_key_enc, exp_key_dec);

        return 0;
}
