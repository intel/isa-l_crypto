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

/**
 * @brief Library error types
 */
typedef enum {
        ISAL_CRYPTO_ERR_NONE = 0,
        ISAL_CRYPTO_ERR_NULL_SRC = 2000,
        ISAL_CRYPTO_ERR_NULL_DST,
        ISAL_CRYPTO_ERR_NULL_CTX,
        ISAL_CRYPTO_ERR_NULL_MGR,
        ISAL_CRYPTO_ERR_NULL_KEY,
        ISAL_CRYPTO_ERR_NULL_EXP_KEY,
        ISAL_CRYPTO_ERR_NULL_IV,
        ISAL_CRYPTO_ERR_NULL_AUTH,
        ISAL_CRYPTO_ERR_NULL_AAD,
        ISAL_CRYPTO_ERR_CIPH_LEN,
        ISAL_CRYPTO_ERR_AUTH_TAG_LEN,
        ISAL_CRYPTO_ERR_INVALID_FLAGS,
        ISAL_CRYPTO_ERR_ALREADY_PROCESSING,
        ISAL_CRYPTO_ERR_ALREADY_COMPLETED,
        ISAL_CRYPTO_ERR_XTS_NULL_TWEAK,
        ISAL_CRYPTO_ERR_XTS_SAME_KEYS,
        ISAL_CRYPTO_ERR_SELF_TEST,
        ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO,
        ISAL_CRYPTO_ERR_WINDOW_SIZE,
        ISAL_CRYPTO_ERR_NULL_OFFSET,
        ISAL_CRYPTO_ERR_NULL_MATCH,
        ISAL_CRYPTO_ERR_NULL_MASK,
        ISAL_CRYPTO_ERR_NULL_INIT_VAL,
        /* add new error types above this comment */
        ISAL_CRYPTO_ERR_MAX /* don't move this one */
} ISAL_CRYPTO_ERROR;

/**
 * @brief Run all crypto self tests
 *
 * When FIPS Mode is enabled, all isal_XXX API which performs any crypto processing
 * on a NIST-approved algorithm (such as isal_aes_cbc_enc_128) will require this function
 * to be run.
 *
 * This API can be run from the application or it will be run internally in the library,
 * after calling any of the isal_XXX API.
 *
 * Either way, once the self tests have passed, all API calls will be able to start
 * performing the crypto operation. If the self tests fail, no crypto processing will be done.
 *
 * This function is thread safe, so only one thread will run the tests and the rest of the threads
 * will wait until the tests are finished.
 *
 * @return  Self test result
 * @retval  0 on success, ISAL_CRYPTO_ERR_SELF_TEST on failure
 */
int
isal_self_tests(void);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _ISAL_CRYPTO_API_H
