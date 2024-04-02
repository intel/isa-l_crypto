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

struct test_func {
	aes_keyexp_func func_ptr;
	char *func_name;
};

static int test_aes_keyexp_api(aes_keyexp_func aes_keyexp_func_ptr, const char *name)
{
	int ret;
	uint8_t key[CBC_ROUND_KEY_LEN] = { 0 };
	uint8_t enc_keys[CBC_MAX_KEYS_SIZE] = { 0 };
	uint8_t dec_keys[CBC_MAX_KEYS_SIZE] = { 0 };

	// test null key
	ret = aes_keyexp_func_ptr(NULL, enc_keys, dec_keys);
	CHECK_RETURN(ret, ISAL_CRYPTO_ERR_NULL_KEY, name);

	// test null exp key ptr
	ret = aes_keyexp_func_ptr(key, NULL, dec_keys);
	CHECK_RETURN(ret, ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

	// test null exp key ptr
	ret = aes_keyexp_func_ptr(key, enc_keys, NULL);
	CHECK_RETURN(ret, ISAL_CRYPTO_ERR_NULL_EXP_KEY, name);

	// test valid params
	ret = aes_keyexp_func_ptr(key, enc_keys, dec_keys);
	CHECK_RETURN(ret, ISAL_CRYPTO_ERR_NONE, name);

	return 0;
}
#endif /* SAFE_PARAM */

int main(void)
{
	int fail = 0;
#ifdef SAFE_PARAM
	const struct test_func test_funcs[] = {
		{isal_aes_keyexp_128, "isal_aes_keyexp_128"},
		{isal_aes_keyexp_192, "isal_aes_keyexp_192"},
		{isal_aes_keyexp_256, "isal_aes_keyexp_256"},
	};

	for (int i = 0; i < DIM(test_funcs); i++) {
		fail |= test_aes_keyexp_api(test_funcs[i].func_ptr, test_funcs[i].func_name);
	}

	printf(fail ? "Fail\n" : "Pass\n");
#else
	printf("Not Executed\n");
#endif
	return fail;
}
