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
#include "md5_mb.h"

#ifndef FIPS_MODE
#define TEST_LEN  (1024 * 1024)
#define TEST_BUFS 100
#ifndef RANDOMS
#define RANDOMS 10
#endif
#ifndef TEST_SEED
#define TEST_SEED 0x1234
#endif

#define UPDATE_SIZE            13 * ISAL_MD5_BLOCK_SIZE
#define MAX_RAND_UPDATE_BLOCKS (TEST_LEN / (16 * ISAL_MD5_BLOCK_SIZE))

#ifdef DEBUG
#define debug_char(x) putchar(x)
#else
#define debug_char(x)                                                                              \
        do {                                                                                       \
        } while (0)
#endif

/* Reference digest global to reduce stack usage */
static uint32_t digest_ref[TEST_BUFS][ISAL_MD5_DIGEST_NWORDS];

extern void
md5_ref(uint8_t *input_data, uint32_t *digest, uint32_t len);

// Generates pseudo-random data

void
rand_buffer(unsigned char *buf, const long buffer_size)
{
        long i;
        for (i = 0; i < buffer_size; i++)
                buf[i] = rand();
}
#endif

int
main(void)
{
#ifndef FIPS_MODE
        ISAL_MD5_HASH_CTX_MGR *mgr = NULL;
        ISAL_MD5_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
        uint32_t i, j, fail = 0;
        uint32_t len_done, len_rem, len_rand;
        unsigned char *bufs[TEST_BUFS] = { 0 };
        unsigned char *buf_ptr[TEST_BUFS];
        uint32_t lens[TEST_BUFS];
        unsigned int joblen, jobs, t;
        int ret;

        printf("multibinary_md5_update test, %d sets of %dx%d max: ", RANDOMS, TEST_BUFS, TEST_LEN);

        srand(TEST_SEED);

        ret = posix_memalign((void *) &mgr, 16, sizeof(ISAL_MD5_HASH_CTX_MGR));
        if ((ret != 0) || (mgr == NULL)) {
                printf("posix_memalign failed test aborted\n");
                return 1;
        }

        ret = isal_md5_ctx_mgr_init(mgr);
        if (ret)
                return 1;

        for (i = 0; i < TEST_BUFS; i++) {
                // Allocate and fill buffer
                bufs[i] = (unsigned char *) malloc(TEST_LEN);
                buf_ptr[i] = bufs[i];
                if (bufs[i] == NULL) {
                        printf("malloc failed test aborted\n");
                        fail++;
                        goto end;
                }
                rand_buffer(bufs[i], TEST_LEN);

                // Init ctx contents
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);

                // Run reference test
                md5_ref(bufs[i], digest_ref[i], TEST_LEN);
        }

        // Run sb_md5 tests
        for (i = 0; i < TEST_BUFS;) {
                len_done = (int) ((uintptr_t) buf_ptr[i] - (uintptr_t) bufs[i]);
                len_rem = TEST_LEN - len_done;

                if (len_done == 0)
                        ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                      UPDATE_SIZE, ISAL_HASH_FIRST);
                else if (len_rem <= UPDATE_SIZE)
                        ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i], len_rem,
                                                      ISAL_HASH_LAST);
                else
                        ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                      UPDATE_SIZE, ISAL_HASH_UPDATE);
                if (ret)
                        return 1;

                // Add jobs while available or finished
                if ((ctx == NULL) || isal_hash_ctx_complete(ctx)) {
                        i++;
                        continue;
                }
                // Resubmit unfinished job
                i = (uint32_t) (uintptr_t) (ctx->user_data);
                buf_ptr[i] += UPDATE_SIZE;
        }

        // Start flushing finished jobs, end on last flushed
        ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
        if (ret)
                return 1;
        while (ctx) {
                if (isal_hash_ctx_complete(ctx)) {
                        debug_char('-');
                        ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
                        if (ret)
                                return 1;
                        continue;
                }
                // Resubmit unfinished job
                i = (uint32_t) (uintptr_t) (ctx->user_data);
                buf_ptr[i] += UPDATE_SIZE;

                len_done = (uint32_t) ((uintptr_t) buf_ptr[i] - (uintptr_t) bufs[i]);
                len_rem = TEST_LEN - len_done;

                if (len_rem <= UPDATE_SIZE)
                        ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i], len_rem,
                                                      ISAL_HASH_LAST);
                else
                        ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                      UPDATE_SIZE, ISAL_HASH_UPDATE);
                if (ret)
                        return 1;

                if (ctx == NULL) {
                        ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
                        if (ret)
                                return 1;
                }
        }

        // Check digests
        for (i = 0; i < TEST_BUFS; i++) {
                for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] != digest_ref[i][j]) {
                                fail++;
                                printf("Test%d fixed size, digest%d fail %8X <=> %8X", i, j,
                                       ctxpool[i].job.result_digest[j], digest_ref[i][j]);
                        }
                }
        }
        putchar('.');

        // Run tests with random size and number of jobs
        for (t = 0; t < RANDOMS; t++) {
                jobs = rand() % (TEST_BUFS);

                for (i = 0; i < jobs; i++) {
                        joblen = rand() % (TEST_LEN);
                        rand_buffer(bufs[i], joblen);
                        lens[i] = joblen;
                        buf_ptr[i] = bufs[i];
                        md5_ref(bufs[i], digest_ref[i], lens[i]);
                }

                ret = isal_md5_ctx_mgr_init(mgr);
                if (ret)
                        return 1;

                // Run md5_sb jobs
                i = 0;
                while (i < jobs) {
                        // Submit a new job
                        len_rand = ISAL_MD5_BLOCK_SIZE +
                                   ISAL_MD5_BLOCK_SIZE * (rand() % MAX_RAND_UPDATE_BLOCKS);

                        if (lens[i] > len_rand)
                                ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                              len_rand, ISAL_HASH_FIRST);
                        else
                                ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                              lens[i], ISAL_HASH_ENTIRE);
                        if (ret)
                                return 1;

                        // Returned ctx could be:
                        //  - null context (we are just getting started and lanes aren't full yet),
                        //  or
                        //  - finished already (an ENTIRE we submitted or a previous LAST is
                        //  returned), or
                        //  - an unfinished ctx, we will resubmit

                        if ((ctx == NULL) || isal_hash_ctx_complete(ctx)) {
                                i++;
                                continue;
                        } else {
                                // unfinished ctx returned, choose another random update length and
                                // submit either UPDATE or LAST depending on the amount of buffer
                                // remaining
                                while ((ctx != NULL) && !(isal_hash_ctx_complete(ctx))) {
                                        j = (uint32_t) (uintptr_t) (ctx->user_data); // Get index of
                                                                                     // the returned
                                                                                     // ctx
                                        buf_ptr[j] = bufs[j] + ctx->total_length;
                                        len_rand = (rand() % ISAL_MD5_BLOCK_SIZE) *
                                                   (rand() % MAX_RAND_UPDATE_BLOCKS);
                                        len_rem = lens[j] - (uint32_t) ctx->total_length;

                                        if (len_rem <=
                                            len_rand) // submit the rest of the job as LAST
                                                ret = isal_md5_ctx_mgr_submit(
                                                        mgr, &ctxpool[j], &ctx, buf_ptr[j], len_rem,
                                                        ISAL_HASH_LAST);
                                        else // submit the random update length as UPDATE
                                                ret = isal_md5_ctx_mgr_submit(
                                                        mgr, &ctxpool[j], &ctx, buf_ptr[j],
                                                        len_rand, ISAL_HASH_UPDATE);
                                        if (ret)
                                                return 1;
                                } // Either continue submitting any contexts returned here as
                                  // UPDATE/LAST, or
                                // go back to submitting new jobs using the index i.

                                i++;
                        }
                }

                // Start flushing finished jobs, end on last flushed
                ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
                if (ret)
                        return 1;
                while (ctx) {
                        if (isal_hash_ctx_complete(ctx)) {
                                debug_char('-');
                                ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
                                if (ret)
                                        return 1;
                                continue;
                        }
                        // Resubmit unfinished job
                        i = (uint32_t) (uintptr_t) (ctx->user_data);
                        buf_ptr[i] = bufs[i] + ctx->total_length; // update buffer pointer
                        len_rem = lens[i] - (uint32_t) ctx->total_length;
                        len_rand =
                                (rand() % ISAL_MD5_BLOCK_SIZE) * (rand() % MAX_RAND_UPDATE_BLOCKS);
                        debug_char('+');
                        if (len_rem <= len_rand)
                                ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                              len_rem, ISAL_HASH_LAST);
                        else
                                ret = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                              len_rand, ISAL_HASH_UPDATE);
                        if (ret)
                                return 1;

                        if (ctx == NULL) {
                                ret = isal_md5_ctx_mgr_flush(mgr, &ctx);
                                if (ret)
                                        return 1;
                        }
                }

                // Check result digest
                for (i = 0; i < jobs; i++) {
                        for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                                if (ctxpool[i].job.result_digest[j] != digest_ref[i][j]) {
                                        fail++;
                                        printf("Test%d, digest%d fail %8X <=> %8X\n", i, j,
                                               ctxpool[i].job.result_digest[j], digest_ref[i][j]);
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

end:
        for (i = 0; i < TEST_BUFS; i++)
                free(bufs[i]);
        aligned_free(mgr);

        if (fail) {
                printf("Test failed function check %d\n", fail);
        } else
                printf(" multibinary_md5_update rand: Pass\n");

        return fail;
#else
        printf("Not Executed\n");

        return 0;
#endif /* FIPS_MODE */
}
