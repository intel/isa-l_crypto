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
#include "isal_crypto_api.h"
#include "rolling_hashx.h"
#include "multi_buffer.h"
#include "test.h"

#ifdef SAFE_PARAM

static int
test_rolling_hash2_init_api(void)
{
        int ret = -1;
        const char *fn_name = "isal_rolling_hash2_init";
        struct isal_rh_state2 state = { 0 };

#ifdef FIPS_MODE
        // check for invalid algorithm
        CHECK_RETURN_GOTO(isal_rolling_hash2_init(&state, 5), ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO,
                          fn_name, end_init);
#else
        // check NULL state
        CHECK_RETURN_GOTO(isal_rolling_hash2_init(NULL, 32), ISAL_CRYPTO_ERR_NULL_CTX, fn_name,
                          end_init);
        // check invalid window size
        CHECK_RETURN_GOTO(isal_rolling_hash2_init(&state, 500), ISAL_CRYPTO_ERR_WINDOW_SIZE,
                          fn_name, end_init);

        // check valid args
        CHECK_RETURN_GOTO(isal_rolling_hash2_init(&state, 5), ISAL_CRYPTO_ERR_NONE, fn_name,
                          end_init);
#endif

        ret = 0;
end_init:
        return ret;
}

static int
test_rolling_hash2_reset_api(void)
{
        int ret = -1;
        const char *fn_name = "isal_rolling_hash2_reset";
        struct isal_rh_state2 state = { 0 };
        uint8_t init_bytes[64] = { 0 };

#ifdef FIPS_MODE
        // check for invalid algorithm
        CHECK_RETURN_GOTO(isal_rolling_hash2_reset(&state, init_bytes),
                          ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, fn_name, end_reset);
#else
        // check NULL state
        CHECK_RETURN_GOTO(isal_rolling_hash2_reset(NULL, init_bytes), ISAL_CRYPTO_ERR_NULL_CTX,
                          fn_name, end_reset);

        // check NULL init bytes
        CHECK_RETURN_GOTO(isal_rolling_hash2_reset(&state, NULL), ISAL_CRYPTO_ERR_NULL_INIT_VAL,
                          fn_name, end_reset);

        // check valid args
        CHECK_RETURN_GOTO(isal_rolling_hash2_reset(&state, init_bytes), ISAL_CRYPTO_ERR_NONE,
                          fn_name, end_reset);
#endif

        ret = 0;
end_reset:
        return ret;
}

static int
test_rolling_hash2_run_api(void)
{
        int ret = -1;
        const char *fn_name = "isal_rolling_hash2_run";
        struct isal_rh_state2 state = { 0 };
        uint8_t buffer[64] = { 0 };
        uint32_t len = (uint32_t) sizeof(buffer);
        uint32_t mask = 0xffff0;
        uint32_t trigger = 0x3df0;
        uint32_t offset = 0;
        int match = -1;

#ifdef FIPS_MODE
        // check for invalid algorithm
        CHECK_RETURN_GOTO(
                isal_rolling_hash2_run(&state, buffer, len, mask, trigger, &offset, &match),
                ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, fn_name, end_run);
#else
        // check NULL state
        CHECK_RETURN_GOTO(isal_rolling_hash2_run(NULL, buffer, len, mask, trigger, &offset, &match),
                          ISAL_CRYPTO_ERR_NULL_CTX, fn_name, end_run);

        // check NULL source buffer
        CHECK_RETURN_GOTO(isal_rolling_hash2_run(&state, NULL, len, mask, trigger, &offset, &match),
                          ISAL_CRYPTO_ERR_NULL_SRC, fn_name, end_run);

        // check NULL offset
        CHECK_RETURN_GOTO(isal_rolling_hash2_run(&state, buffer, len, mask, trigger, NULL, &match),
                          ISAL_CRYPTO_ERR_NULL_OFFSET, fn_name, end_run);

        // check NULL match
        CHECK_RETURN_GOTO(isal_rolling_hash2_run(&state, buffer, len, mask, trigger, &offset, NULL),
                          ISAL_CRYPTO_ERR_NULL_MATCH, fn_name, end_run);

        // check valid args
        CHECK_RETURN_GOTO(
                isal_rolling_hash2_run(&state, buffer, len, mask, trigger, &offset, &match),
                ISAL_CRYPTO_ERR_NONE, fn_name, end_run);
#endif

        ret = 0;
end_run:
        return ret;
}

static int
test_rolling_hashx_mask_gen_api(void)
{
        int ret = -1;
        const char *fn_name = "isal_rolling_hashx_mask_gen";
        uint32_t mean = 0;
        uint32_t shift = 0;
        uint32_t mask = ISAL_FINGERPRINT_RET_OTHER + 1;

#ifdef FIPS_MODE
        // check for invalid algorithm
        CHECK_RETURN_GOTO(isal_rolling_hashx_mask_gen(mean, shift, &mask),
                          ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO, fn_name, end_mask_gen);
#else
        // check NULL mask
        CHECK_RETURN_GOTO(isal_rolling_hashx_mask_gen(mean, shift, NULL), ISAL_CRYPTO_ERR_NULL_MASK,
                          fn_name, end_mask_gen);

        // check valid args
        CHECK_RETURN_GOTO(isal_rolling_hashx_mask_gen(mean, shift, &mask), ISAL_CRYPTO_ERR_NONE,
                          fn_name, end_mask_gen);

        // check mask was set to valid value
        if (mask >= ISAL_FINGERPRINT_RET_OTHER) {
                printf("test: %s() - unexpected mask set\n", fn_name);
                goto end_mask_gen;
        }
#endif

        ret = 0;
end_mask_gen:
        return ret;
}

#endif /* SAFE_PARAM */

int
main(void)
{
        int fail = 0;

#ifdef SAFE_PARAM
        fail |= test_rolling_hash2_init_api();
        fail |= test_rolling_hash2_reset_api();
        fail |= test_rolling_hash2_run_api();
        fail |= test_rolling_hashx_mask_gen_api();

        printf(fail ? "Fail\n" : "Pass\n");
#else
        printf("Not Executed\n");
#endif
        return fail;
}
