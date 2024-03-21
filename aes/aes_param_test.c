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
#include "isal_crypto_api.h"
#include "aes_keyexp.h"
#include "aes_cbc.h"
#include "test.h"

#ifdef SAFE_PARAM
#define CHECK_RETURN(state, expected, func)	do{ \
	if((state) != (expected)){ \
		printf("test: %s() - expected return " \
		       "value %d, got %d\n", func, expected, state); \
		return 1; \
	} \
}while(0)

typedef int (*aes_keyexp_func)(const uint8_t *, uint8_t *, uint8_t *);
typedef int (*aes_cbc_func)(const void *, const uint8_t *, const uint8_t *,
			    void *, const uint64_t);

struct test_func {
	union {
		aes_keyexp_func keyexp_func_ptr;
		aes_cbc_func cbc_func_ptr;
	};
	char *func_name;
};

static int test_aes_keyexp_api(aes_keyexp_func aes_keyexp_func_ptr, const char *name)
{
	uint8_t key[CBC_ROUND_KEY_LEN] = { 0 };
	uint8_t enc_keys[CBC_MAX_KEYS_SIZE] = { 0 };
	uint8_t dec_keys[CBC_MAX_KEYS_SIZE] = { 0 };

	// test null key
	CHECK_RETURN(aes_keyexp_func_ptr(NULL, enc_keys, dec_keys), ISAL_CRYPTO_ERR_NULL_KEY,
		     name);

	// test null exp key ptr
	CHECK_RETURN(aes_keyexp_func_ptr(key, NULL, dec_keys), ISAL_CRYPTO_ERR_NULL_EXP_KEY,
		     name);

	// test null exp key ptr
	CHECK_RETURN(aes_keyexp_func_ptr(key, enc_keys, NULL), ISAL_CRYPTO_ERR_NULL_EXP_KEY,
		     name);

	// test valid params
	CHECK_RETURN(aes_keyexp_func_ptr(key, enc_keys, dec_keys), ISAL_CRYPTO_ERR_NONE, name);

	return 0;
}

static int test_aes_cbc_api(aes_cbc_func aes_cbc_func_ptr, const char *name)
{
	uint8_t exp_keys[CBC_MAX_KEYS_SIZE] = { 0 };
	uint8_t buf[16] = { 0 };
	uint8_t iv[16] = { 0 };

	// test null input ptr
	CHECK_RETURN(aes_cbc_func_ptr(NULL, iv, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NULL_SRC,
		     name);

	// test null IV ptr
	CHECK_RETURN(aes_cbc_func_ptr(buf, NULL, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NULL_IV,
		     name);

	// test null exp key ptr
	CHECK_RETURN(aes_cbc_func_ptr(buf, iv, NULL, buf, 16), ISAL_CRYPTO_ERR_NULL_EXP_KEY,
		     name);

	// test null output ptr
	CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, NULL, 16), ISAL_CRYPTO_ERR_NULL_DST,
		     name);

	// test invalid length (not multiple of 16 bytes)
	CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, buf, 15), ISAL_CRYPTO_ERR_CIPH_LEN,
		     name);

	// test valid params
	CHECK_RETURN(aes_cbc_func_ptr(buf, iv, exp_keys, buf, 16), ISAL_CRYPTO_ERR_NONE, name);

	return 0;
}

#endif /* SAFE_PARAM */

int main(void)
{
	int fail = 0;
#ifdef SAFE_PARAM
	/* Test AES key expansion API */
	const struct test_func keyexp_test_funcs[] = {
		{.keyexp_func_ptr = isal_aes_keyexp_128, "isal_aes_keyexp_128"},
		{.keyexp_func_ptr = isal_aes_keyexp_192, "isal_aes_keyexp_192"},
		{.keyexp_func_ptr = isal_aes_keyexp_256, "isal_aes_keyexp_256"},
	};

	for (int i = 0; i < DIM(keyexp_test_funcs); i++) {
		fail |=
		    test_aes_keyexp_api(keyexp_test_funcs[i].keyexp_func_ptr,
					keyexp_test_funcs[i].func_name);
	}

	/* Test AES-CBC API */
	const struct test_func cbc_test_funcs[] = {
		{.cbc_func_ptr = isal_aes_cbc_enc_128, "isal_aes_cbc_enc_128"},
		{.cbc_func_ptr = isal_aes_cbc_enc_192, "isal_aes_cbc_enc_192"},
		{.cbc_func_ptr = isal_aes_cbc_enc_256, "isal_aes_cbc_enc_256"},
		{.cbc_func_ptr = isal_aes_cbc_dec_128, "isal_aes_cbc_dec_128"},
		{.cbc_func_ptr = isal_aes_cbc_dec_192, "isal_aes_cbc_dec_192"},
		{.cbc_func_ptr = isal_aes_cbc_dec_256, "isal_aes_cbc_dec_256"},
	};

	for (int i = 0; i < DIM(cbc_test_funcs); i++) {
		fail |=
		    test_aes_cbc_api(cbc_test_funcs[i].cbc_func_ptr,
				     cbc_test_funcs[i].func_name);
	}

	printf(fail ? "Fail\n" : "Pass\n");
#else
	printf("Not Executed\n");
#endif
	return fail;
}
