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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isal_crypto_api.h"
#include "mh_sha256.h"
#include "test.h"

#ifdef SAFE_PARAM
#define TEST_LEN 16 * 1024

static int
test_mh_sha256_init_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha256_ctx *update_ctx = NULL;
        const char *func_name = "isal_mh_sha256_init";

        update_ctx = malloc(sizeof(*update_ctx));
        if (update_ctx == NULL) {
                printf("malloc failed test aborted\n");
                return retval;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha256_init(update_ctx);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_init);
#else
        ret = isal_mh_sha256_init(NULL);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_init);

        ret = isal_mh_sha256_init(update_ctx);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_init);
#endif
        retval = 0;

exit_init:
        free(update_ctx);

        return retval;
}

static int
test_mh_sha256_update_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha256_ctx *update_ctx = NULL;
        uint8_t *buff = NULL;
        const char *func_name = "isal_mh_sha256_update";

        update_ctx = malloc(sizeof(*update_ctx));
        buff = malloc(TEST_LEN);
        if (update_ctx == NULL || buff == NULL) {
                printf("malloc failed test aborted\n");
                goto exit_update;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha256_update(update_ctx, buff, TEST_LEN);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_update);
#else
        ret = isal_mh_sha256_update(NULL, buff, TEST_LEN);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_update);

        ret = isal_mh_sha256_update(update_ctx, NULL, TEST_LEN);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_SRC, func_name, exit_update);

        ret = isal_mh_sha256_update(update_ctx, buff, TEST_LEN);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_update);
#endif

        retval = 0;

exit_update:
        free(update_ctx);
        free(buff);

        return retval;
}

static int
test_mh_sha256_finalize_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha256_ctx *update_ctx = NULL;
        uint32_t hash_test[ISAL_SHA256_DIGEST_WORDS] = { 0 };
        const char *func_name = "isal_mh_sha256_finalize";

        update_ctx = malloc(sizeof(*update_ctx));
        if (update_ctx == NULL) {
                printf("malloc failed test aborted\n");
                return retval;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha256_finalize(update_ctx, hash_test);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_finalize);
#else
        ret = isal_mh_sha256_finalize(NULL, hash_test);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_finalize);

        ret = isal_mh_sha256_finalize(update_ctx, NULL);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_AUTH, func_name, exit_finalize);

        ret = isal_mh_sha256_finalize(update_ctx, hash_test);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_finalize);
#endif
        retval = 0;

exit_finalize:
        free(update_ctx);

        return retval;
}
#endif /* SAFE_PARAM */

int
main(void)
{
        int fail = 0;
#ifdef SAFE_PARAM
        fail |= test_mh_sha256_init_api();
        fail |= test_mh_sha256_update_api();
        fail |= test_mh_sha256_finalize_api();
        printf(fail ? "Fail\n" : "Pass\n");
#else
        printf("Not Executed\n");
#endif
        return fail;
}
