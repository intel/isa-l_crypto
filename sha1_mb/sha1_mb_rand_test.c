/**********************************************************************
  Copyright(c) 2011-2016 Intel Corporation All rights reserved.

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
#include "sha1_mb.h"

#define TEST_LEN  (1024 * 1024)
#define TEST_BUFS 100
#ifndef RANDOMS
#define RANDOMS 10
#endif
#ifndef TEST_SEED
#define TEST_SEED 0x1234
#endif

static uint32_t digest_ref[TEST_BUFS][ISAL_SHA1_DIGEST_NWORDS];

// Compare against reference function
extern void
sha1_ref(uint8_t *input_data, uint32_t *digest, uint32_t len);

// Generates pseudo-random data
void
rand_buffer(unsigned char *buf, const long buffer_size)
{
        long i;
        for (i = 0; i < buffer_size; i++)
                buf[i] = rand();
}

int
main(void)
{
        ISAL_SHA1_HASH_CTX_MGR *mgr = NULL;
        ISAL_SHA1_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
        uint32_t i, j, fail = 0;
        unsigned char *bufs[TEST_BUFS];
        uint32_t lens[TEST_BUFS];
        unsigned int jobs, t;
        uint8_t *tmp_buf = NULL;
        int ret;

        printf("multibinary_sha1 test, %d sets of %dx%d max: ", RANDOMS, TEST_BUFS, TEST_LEN);

        ret = posix_memalign((void *) &mgr, 16, sizeof(ISAL_SHA1_HASH_CTX_MGR));
        if ((ret != 0) || (mgr == NULL)) {
                printf("posix_memalign failed test aborted\n");
                return 1;
        }

        ret = isal_sha1_ctx_mgr_init(mgr);
        if (ret)
                return 1;

        srand(TEST_SEED);

        for (i = 0; i < TEST_BUFS; i++) {
                // Allocate  and fill buffer
                bufs[i] = (unsigned char *) malloc(TEST_LEN);
                if (bufs[i] == NULL) {
                        printf("malloc failed test aborted\n");
                        fail++;
                        goto end;
                }
                rand_buffer(bufs[i], TEST_LEN);

                // Init ctx contexts
                hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);

                // Run reference test
                sha1_ref(bufs[i], digest_ref[i], TEST_LEN);

                // Run sb_sha1 test
                ret = isal_sha1_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, bufs[i], TEST_LEN,
                                               HASH_ENTIRE);
                if (ret)
                        return 1;
        }

        do {
                ret = isal_sha1_ctx_mgr_flush(mgr, &ctx);
                if (ret)
                        return 1;
        } while (ctx != NULL);

        for (i = 0; i < TEST_BUFS; i++) {
                for (j = 0; j < ISAL_SHA1_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] != digest_ref[i][j]) {
                                fail++;
                                printf("Test%d fixed size, digest%d "
                                       "fail 0x%08X <=> 0x%08X \n",
                                       i, j, ctxpool[i].job.result_digest[j], digest_ref[i][j]);
                        }
                }
        }

        if (fail) {
                printf("Test failed function check %d\n", fail);
                goto end;
        }
        // Run tests with random size and number of jobs
        for (t = 0; t < RANDOMS; t++) {
                jobs = rand() % (TEST_BUFS);

                ret = isal_sha1_ctx_mgr_init(mgr);
                if (ret)
                        return 1;

                for (i = 0; i < jobs; i++) {
                        // Use buffer with random len and contents
                        lens[i] = rand() % (TEST_LEN);
                        rand_buffer(bufs[i], lens[i]);

                        // Run reference test
                        sha1_ref(bufs[i], digest_ref[i], lens[i]);

                        // Run sha1_mb test
                        ret = isal_sha1_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, bufs[i], lens[i],
                                                       HASH_ENTIRE);
                        if (ret)
                                return 1;
                }

                do {
                        ret = isal_sha1_ctx_mgr_flush(mgr, &ctx);
                        if (ret)
                                return 1;
                } while (ctx != NULL);

                for (i = 0; i < jobs; i++) {
                        for (j = 0; j < ISAL_SHA1_DIGEST_NWORDS; j++) {
                                if (ctxpool[i].job.result_digest[j] != digest_ref[i][j]) {
                                        fail++;
                                        printf("Test%d, digest%d fail "
                                               "0x%08X <=> 0x%08X\n",
                                               i, j, ctxpool[i].job.result_digest[j],
                                               digest_ref[i][j]);
                                }
                        }
                }
                if (fail) {
                        printf("Test failed function check %d\n", fail);
                        goto end;
                }

                putchar('.');
                fflush(0);
        } // random test t

        // Test at the end of buffer
        jobs = rand() % TEST_BUFS;
        tmp_buf = (uint8_t *) malloc(sizeof(uint8_t) * jobs);
        if (!tmp_buf) {
                printf("malloc failed, end test aborted.\n");
                goto end;
        }

        rand_buffer(tmp_buf, jobs);

        ret = isal_sha1_ctx_mgr_init(mgr);
        if (ret)
                return 1;

        for (i = 0; i < TEST_BUFS; i++)
                free(bufs[i]);

        // Extend to the end of allocated buffer to construct jobs
        for (i = 0; i < jobs; i++) {
                bufs[i] = (uint8_t *) &tmp_buf[i];
                lens[i] = jobs - i;

                // Reference test
                sha1_ref(bufs[i], digest_ref[i], lens[i]);

                // sb_sha1 test
                ret = isal_sha1_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, bufs[i], lens[i],
                                               HASH_ENTIRE);
                if (ret)
                        return 1;
        }
        // Clear bufs
        memset(bufs, 0, sizeof(bufs));

        do {
                ret = isal_sha1_ctx_mgr_flush(mgr, &ctx);
                if (ret)
                        return 1;
        } while (ctx != NULL);

        for (i = 0; i < jobs; i++) {
                for (j = 0; j < ISAL_SHA1_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] != digest_ref[i][j]) {
                                fail++;
                                printf("End test failed at offset %d - result: 0x%08X"
                                       ", ref: 0x%08X\n",
                                       i, ctxpool[i].job.result_digest[j], digest_ref[i][j]);
                        }
                }
        }
        putchar('.');

end:
        for (i = 0; i < TEST_BUFS; i++)
                free(bufs[i]);
        free(tmp_buf);
        aligned_free(mgr);

        if (fail)
                printf("Test failed function check %d\n", fail);
        else
                printf(" multibinary_sha1 rand: Pass\n");

        return fail;
}
