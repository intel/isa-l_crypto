/**********************************************************************
  Copyright(c) 2011-2019 Intel Corporation All rights reserved.

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
#define ISAL_UNIT_TEST
#include <stdio.h>
#include <stdlib.h>
#include "sm3_mb.h"

#define TEST_LEN  (1024*1024)
#define TEST_BUFS (SM3_MAX_LANES - 1)
#ifndef TEST_SEED
# define TEST_SEED 0x1234
#endif

static uint8_t digest_ref[TEST_BUFS][4 * SM3_DIGEST_NWORDS];

// Compare against reference function
extern void sm3_ossl(const unsigned char *buf, size_t length, unsigned char *digest);

// Generates pseudo-random data
void rand_buffer(unsigned char *buf, const long buffer_size)
{
	long i;
	for (i = 0; i < buffer_size; i++)
		buf[i] = rand();
}

uint8_t lens_print_and_check(SM3_HASH_CTX_MGR * mgr)
{
	static int32_t last_lens[SM3_MAX_LANES] = { 0 };
	int32_t len;
	uint8_t num_unchanged = 0;
	int i;
	for (i = 0; i < SM3_MAX_LANES; i++) {
		len = (int32_t) mgr->mgr.lens[i];
		// len[i] in mgr consists of byte_length<<4 | lane_index
		len = (len >= 16) ? (len >> 4 << 6) : 0;
		printf("\t%d", len);
		if (last_lens[i] > 0 && last_lens[i] == len)
			num_unchanged += 1;
		last_lens[i] = len;
	}
	printf("\n");
	return num_unchanged;
}

int main(void)
{
	SM3_HASH_CTX_MGR *mgr = NULL;
	SM3_HASH_CTX ctxpool[TEST_BUFS];
	uint32_t i, j, fail = 0;
	unsigned char *bufs[TEST_BUFS];
	uint32_t lens[TEST_BUFS];
	uint8_t num_ret, num_unchanged = 0;

	printf("sm3_mb flush test, %d buffers with %d length: \n", TEST_BUFS, TEST_LEN);

	posix_memalign((void *)&mgr, 16, sizeof(SM3_HASH_CTX_MGR));
	sm3_ctx_mgr_init(mgr);

	srand(TEST_SEED);

	for (i = 0; i < TEST_BUFS; i++) {
		// Allocate  and fill buffer
		lens[i] = TEST_LEN / SM3_MAX_LANES * (i + 1);
		bufs[i] = (unsigned char *)malloc(lens[i]);
		if (bufs[i] == NULL) {
			printf("malloc failed test aborted\n");
			return 1;
		}
		rand_buffer(bufs[i], lens[i]);
	}

	for (i = 0; i < TEST_BUFS; i++) {
		// Init ctx contexts
		hash_ctx_init(&ctxpool[i]);
		ctxpool[i].user_data = (void *)((uint64_t) i);

		// Run reference test
		sm3_ossl(bufs[i], lens[i], digest_ref[i]);

		// Run sb_sm3 test
		sm3_ctx_mgr_submit(mgr, &ctxpool[i], bufs[i], lens[i], HASH_ENTIRE);
	}

	printf("Changes of lens inside mgr:\n");
	lens_print_and_check(mgr);
	while (sm3_ctx_mgr_flush(mgr)) {
		num_ret = lens_print_and_check(mgr);
		num_unchanged = num_unchanged > num_ret ? num_unchanged : num_ret;
	}
	printf("Info of sm3_mb lens prints over\n");

	for (i = 0; i < TEST_BUFS; i++) {
		for (j = 0; j < SM3_DIGEST_NWORDS; j++) {
			if (ctxpool[i].job.result_digest[j] !=
			    to_le32(((uint32_t *) digest_ref[i])[j])) {
				fail++;
				printf("Test%d fixed size, digest%d "
				       "fail 0x%08X <=> 0x%08X \n",
				       i, j, ctxpool[i].job.result_digest[j],
				       to_le32(((uint32_t *) digest_ref[i])[j]));
			}
		}
	}

	if (fail)
		printf("Test failed function check %d\n", fail);
	else
		printf("Pass\n");

	return fail;
}
