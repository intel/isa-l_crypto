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

#ifndef _ISAL_CRYPTO_API_H
#define _ISAL_CRYPTO_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
        ISAL_CRYPTO_ERR_NONE = 0,
        ISAL_CRYPTO_ERR_NULL_SRC = 2000,
        ISAL_CRYPTO_ERR_NULL_DST,
        ISAL_CRYPTO_ERR_NULL_CTX,
        ISAL_CRYPTO_ERR_NULL_KEY,
        ISAL_CRYPTO_ERR_NULL_EXP_KEY,
        ISAL_CRYPTO_ERR_NULL_IV,
        ISAL_CRYPTO_ERR_NULL_AUTH,
        ISAL_CRYPTO_ERR_NULL_AAD,
        ISAL_CRYPTO_ERR_CIPH_LEN,
        ISAL_CRYPTO_ERR_AUTH_LEN,
        ISAL_CRYPTO_ERR_IV_LEN,
        ISAL_CRYPTO_ERR_KEY_LEN,
        ISAL_CRYPTO_ERR_AUTH_TAG_LEN,
        ISAL_CRYPTO_ERR_AAD_LEN,
        /* add new error types above this comment */
        ISAL_CRYPTO_ERR_MAX /* don't move this one */
} ISAL_CRYPTO_ERROR;

#ifdef __cplusplus
}
#endif //__cplusplus
#endif //ifndef _ISAL_CRYPTO_API_H
