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

/* Utility macros */
#define CONCAT_VERSION_(a, b, c) a##.##b##.##c
#define CONCAT_VERSION(a, b, c)  CONCAT_VERSION_(a, b, c)
#define TO_STRING_(a)            #a
#define TO_STRING(a)             TO_STRING_(a)

/* Library version numbers */
#define ISAL_CRYPTO_MAJOR_VERSION 2
#define ISAL_CRYPTO_MINOR_VERSION 25
#define ISAL_CRYPTO_PATCH_VERSION 0

#define ISAL_CRYPTO_MAKE_VERSION(maj, min, patch) ((maj) * 0x10000 + (min) * 0x100 + (patch))
#define ISAL_CRYPTO_VERSION                                                                        \
        ISAL_CRYPTO_MAKE_VERSION(ISAL_CRYPTO_MAJOR_VERSION, ISAL_CRYPTO_MINOR_VERSION,             \
                                 ISAL_CRYPTO_PATCH_VERSION)
#define ISAL_CRYPTO_VERSION_STR                                                                    \
        TO_STRING(CONCAT_VERSION(ISAL_CRYPTO_MAJOR_VERSION, ISAL_CRYPTO_MINOR_VERSION,             \
                                 ISAL_CRYPTO_PATCH_VERSION))

/**
 * @brief Library error types
 */
typedef enum {
        ISAL_CRYPTO_ERR_NONE = 0,           //!< No error
        ISAL_CRYPTO_ERR_NULL_SRC = 2000,    //!< Null source pointer
        ISAL_CRYPTO_ERR_NULL_DST,           //!< Null destination pointer
        ISAL_CRYPTO_ERR_NULL_CTX,           //!< Null context pointer
        ISAL_CRYPTO_ERR_NULL_MGR,           //!< Null manager pointer
        ISAL_CRYPTO_ERR_NULL_KEY,           //!< Null key pointer
        ISAL_CRYPTO_ERR_NULL_EXP_KEY,       //!< Null expanded key pointer
        ISAL_CRYPTO_ERR_NULL_IV,            //!< Null IV pointer
        ISAL_CRYPTO_ERR_NULL_AUTH,          //!< Null authentication tag pointer
        ISAL_CRYPTO_ERR_NULL_AAD,           //!< Null AAD pointer
        ISAL_CRYPTO_ERR_CIPH_LEN,           //!< Invalid cipher length
        ISAL_CRYPTO_ERR_AUTH_TAG_LEN,       //!< Invalid authentication tag length
        ISAL_CRYPTO_ERR_INVALID_FLAGS,      //!< Invalid context flags
        ISAL_CRYPTO_ERR_ALREADY_PROCESSING, //!< Job already processing
        ISAL_CRYPTO_ERR_ALREADY_COMPLETED,  //!< Job already completed
        ISAL_CRYPTO_ERR_XTS_NULL_TWEAK,     //!< Null AES-XTS tweak pointer
        ISAL_CRYPTO_ERR_XTS_SAME_KEYS,      //!< Equal AES-XTS k1 and k2 keys
        ISAL_CRYPTO_ERR_SELF_TEST,          //!< Self tests
        ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO,  //!< Non NIST-approved algorithm
        ISAL_CRYPTO_ERR_WINDOW_SIZE,        //!< Invalid Rolling hash window size
        ISAL_CRYPTO_ERR_NULL_OFFSET,        //!< Null Rolling hash offset pointer
        ISAL_CRYPTO_ERR_NULL_MATCH,         //!< Null Rolling hash match pointer
        ISAL_CRYPTO_ERR_NULL_MASK,          //!< Null Rolling hash mask pointer
        ISAL_CRYPTO_ERR_NULL_INIT_VAL,      //!< Null Rolling hash initial value pointer
        ISAL_CRYPTO_ERR_FIPS_DISABLED,      //!< FIPS Mode is not enabled
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

/**
 * @brief Get library version in string format
 *
 * @return library version string
 */
const char *
isal_crypto_get_version_str(void);

/**
 * @brief Get library version in numerical format
 *
 * Use ISAL_CRYPTO_MAKE_VERSION macro to compare this
 * numerical version against known library version.
 *
 * @return library version number
 */
unsigned
isal_crypto_get_version(void);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _ISAL_CRYPTO_API_H
