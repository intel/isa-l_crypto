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
#include "sha512_mb.h"
#include "multi_buffer.h"
#include "test.h"

#ifdef SAFE_PARAM

static int test_sha512_mb_init_api(void)
{
	SHA512_HASH_CTX_MGR *mgr = NULL;
	int rc, ret = -1;

	rc = posix_memalign((void *)&mgr, 16, sizeof(SHA512_HASH_CTX_MGR));
	if ((rc != 0) || (mgr == NULL)) {
		printf("posix_memalign failed test aborted\n");
		return 1;
	}
	// check null mgr
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_init(NULL), ISAL_CRYPTO_ERR_NULL_MGR,
			  "isal_sha512_ctx_mgr_init", end_init);

	// check valid args
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_init(mgr), ISAL_CRYPTO_ERR_NONE,
			  "isal_sha512_ctx_mgr_init", end_init);
	ret = 0;

      end_init:
	aligned_free(mgr);

	return ret;
}

static int test_sha512_mb_submit_api(void)
{
	SHA512_HASH_CTX_MGR *mgr = NULL;
	SHA512_HASH_CTX ctx = { 0 }, *ctx_ptr = &ctx;
	int rc, ret = -1;
	const char *fn_name = "isal_sha512_ctx_mgr_submit";
	static uint8_t msg[] = "Test message";

	rc = posix_memalign((void *)&mgr, 16, sizeof(SHA512_HASH_CTX_MGR));
	if ((rc != 0) || (mgr == NULL)) {
		printf("posix_memalign failed test aborted\n");
		return 1;
	}

	rc = isal_sha512_ctx_mgr_init(mgr);
	if (rc != ISAL_CRYPTO_ERR_NONE)
		goto end_submit;

	// Init context before first use
	hash_ctx_init(&ctx);

	// check null mgr
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(NULL, ctx_ptr, &ctx_ptr, msg,
						     strlen((char *)msg),
						     HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_NULL_MGR, fn_name, end_submit);

	// check null input ctx
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit
			  (mgr, NULL, &ctx_ptr, msg, strlen((char *)msg), HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_NULL_CTX, fn_name, end_submit);

	// check null output ctx
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit
			  (mgr, ctx_ptr, NULL, msg, strlen((char *)msg), HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_NULL_CTX, fn_name, end_submit);

	// check null source ptr
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(mgr, ctx_ptr, &ctx_ptr, NULL,
						     strlen((char *)msg),
						     HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_NULL_SRC, fn_name, end_submit);

	// check invalid flag
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(mgr, ctx_ptr, &ctx_ptr, msg,
						     strlen((char *)msg), 999),
			  ISAL_CRYPTO_ERR_INVALID_FLAGS, fn_name, end_submit);

	// simulate internal error (submit in progress job)
	ctx_ptr->status = HASH_CTX_STS_PROCESSING;

	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(mgr, ctx_ptr, &ctx_ptr, msg,
						     strlen((char *)msg),
						     HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_ALREADY_PROCESSING, fn_name, end_submit);

	CHECK_RETURN_GOTO(ctx_ptr->error, HASH_CTX_ERROR_ALREADY_PROCESSING,
			  fn_name, end_submit);

	// simulate internal error (submit completed job)
	ctx_ptr->error = HASH_CTX_ERROR_NONE;
	ctx_ptr->status = HASH_CTX_STS_COMPLETE;

	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(mgr, ctx_ptr, &ctx_ptr, msg,
						     strlen((char *)msg),
						     HASH_UPDATE),
			  ISAL_CRYPTO_ERR_ALREADY_COMPLETED, fn_name, end_submit);

	CHECK_RETURN_GOTO(ctx_ptr->error, HASH_CTX_ERROR_ALREADY_COMPLETED,
			  fn_name, end_submit);

	// check valid args
	hash_ctx_init(&ctx);
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_submit(mgr, ctx_ptr, &ctx_ptr, msg,
						     strlen((char *)msg),
						     HASH_ENTIRE),
			  ISAL_CRYPTO_ERR_NONE, fn_name, end_submit);
	ret = 0;

      end_submit:
	aligned_free(mgr);

	return ret;
}

static int test_sha512_mb_flush_api(void)
{
	SHA512_HASH_CTX_MGR *mgr = NULL;
	SHA512_HASH_CTX ctx = { 0 }, *ctx_ptr = &ctx;
	int rc, ret = -1;
	const char *fn_name = "isal_sha512_ctx_mgr_flush";

	rc = posix_memalign((void *)&mgr, 16, sizeof(SHA512_HASH_CTX_MGR));
	if ((rc != 0) || (mgr == NULL)) {
		printf("posix_memalign failed test aborted\n");
		return 1;
	}

	rc = isal_sha512_ctx_mgr_init(mgr);
	if (rc != ISAL_CRYPTO_ERR_NONE)
		goto end_flush;

	// Init context before first use
	hash_ctx_init(&ctx);

	// check null mgr
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_flush(NULL, &ctx_ptr),
			  ISAL_CRYPTO_ERR_NULL_MGR, fn_name, end_flush);

	// check null ctx
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_flush(mgr, NULL),
			  ISAL_CRYPTO_ERR_NULL_CTX, fn_name, end_flush);

	// check valid args
	CHECK_RETURN_GOTO(isal_sha512_ctx_mgr_flush(mgr, &ctx_ptr),
			  ISAL_CRYPTO_ERR_NONE, fn_name, end_flush);

	if (ctx_ptr != NULL) {
		printf("test: %s() - expected NULL job ptr\n", fn_name);
		goto end_flush;
	}

	ret = 0;

      end_flush:
	aligned_free(mgr);

	return ret;
}
#endif /* SAFE_PARAM */

int main(void)
{
	int fail = 0;

#ifdef SAFE_PARAM
	fail |= test_sha512_mb_init_api();
	fail |= test_sha512_mb_submit_api();
	fail |= test_sha512_mb_flush_api();

	printf(fail ? "Fail\n" : "Pass\n");
#else
	printf("Not Executed\n");
#endif
	return fail;
}
