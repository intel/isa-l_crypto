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
#include "mh_sha1_murmur3_x64_128.h"
#include "test.h"

#ifdef SAFE_PARAM

static int
test_mh_sha1_murmur3_x64_128_init_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha1_murmur3_x64_128_ctx *ctx = NULL;
        const char *func_name = "isal_mh_sha1_murmur3_x64_128_init";
        const uint64_t seed = 0;

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL) {
                printf("malloc failed test aborted\n");
                return retval;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha1_murmur3_x64_128_init(ctx, seed);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_init);
#else
        // check null ctx
        ret = isal_mh_sha1_murmur3_x64_128_init(NULL, seed);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_init);

        // check valid params
        ret = isal_mh_sha1_murmur3_x64_128_init(ctx, seed);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_init);
#endif

        retval = 0;

exit_init:
        free(ctx);

        return retval;
}

static int
test_mh_sha1_murmur3_x64_128_update_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha1_murmur3_x64_128_ctx *ctx = NULL;
        uint8_t *buff = NULL;
        const char *func_name = "isal_mh_sha1_murmur3_x64_128_update";
        const int len = 1024;

        ctx = malloc(sizeof(*ctx));
        buff = malloc(len);
        if (ctx == NULL || buff == NULL) {
                printf("malloc failed test aborted\n");
                goto exit_update;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha1_murmur3_x64_128_update(ctx, buff, len);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_update);
#else
        // check null ctx
        ret = isal_mh_sha1_murmur3_x64_128_update(NULL, buff, len);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_update);

        // check null src buffer
        ret = isal_mh_sha1_murmur3_x64_128_update(ctx, NULL, len);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_SRC, func_name, exit_update);

        // check valid params
        ret = isal_mh_sha1_murmur3_x64_128_update(ctx, buff, len);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_update);
#endif

        retval = 0;

exit_update:
        free(ctx);
        free(buff);

        return retval;
}

static int
test_mh_sha1_murmur3_x64_128_finalize_api(void)
{
        int ret, retval = 1;
        struct isal_mh_sha1_murmur3_x64_128_ctx *ctx = NULL;
        uint32_t mh_sha1_digest[ISAL_SHA1_DIGEST_WORDS];
        uint32_t murmur3_x64_128_digest[ISAL_MURMUR3_x64_128_DIGEST_WORDS];
        const char *func_name = "isal_mh_sha1_murmur3_x64_128_finalize";

        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL) {
                printf("malloc failed test aborted\n");
                return retval;
        }

#ifdef FIPS_MODE
        // Check for invalid algorithm error
        ret = isal_mh_sha1_murmur3_x64_128_finalize(ctx, mh_sha1_digest, murmur3_x64_128_digest);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, func_name, exit_finalize);
#else
        // check null ctx
        ret = isal_mh_sha1_murmur3_x64_128_finalize(NULL, mh_sha1_digest, murmur3_x64_128_digest);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_CTX, func_name, exit_finalize);

        // check null sha1 digest
        ret = isal_mh_sha1_murmur3_x64_128_finalize(ctx, NULL, murmur3_x64_128_digest);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_AUTH, func_name, exit_finalize);

        // check null murmur3 digest
        ret = isal_mh_sha1_murmur3_x64_128_finalize(ctx, mh_sha1_digest, NULL);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NULL_AUTH, func_name, exit_finalize);

        // check valid params
        ret = isal_mh_sha1_murmur3_x64_128_finalize(ctx, mh_sha1_digest, murmur3_x64_128_digest);
        CHECK_RETURN_GOTO(ret, ISAL_CRYPTO_ERR_NONE, func_name, exit_finalize);
#endif

        retval = 0;

exit_finalize:
        free(ctx);

        return retval;
}
#endif /* SAFE_PARAM */

int
main(void)
{
        int fail = 0;
#ifdef SAFE_PARAM
        fail |= test_mh_sha1_murmur3_x64_128_init_api();
        fail |= test_mh_sha1_murmur3_x64_128_update_api();
        fail |= test_mh_sha1_murmur3_x64_128_finalize_api();
        printf(fail ? "Fail\n" : "Pass\n");
#else
        printf("Not Executed\n");
#endif
        return fail;
}
