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

#ifndef FIPS_MODE
#include "sm3_mb.h"
#include "endian_helper.h"

#define TEST_LEN  (1024 * 1024)
#define TEST_BUFS 100
#ifndef RANDOMS
#define RANDOMS 10
#endif
#ifndef TEST_SEED
#define TEST_SEED 0x1234
#endif

#define UPDATE_SIZE            13 * ISAL_SM3_BLOCK_SIZE
#define MAX_RAND_UPDATE_BLOCKS (TEST_LEN / (16 * ISAL_SM3_BLOCK_SIZE))

#ifdef DEBUG
#define debug_char(x) putchar(x)
#else
#define debug_char(x)                                                                              \
        do {                                                                                       \
        } while (0)
#endif

/* Reference digest global to reduce stack usage */
static uint8_t digest_ref[TEST_BUFS][4 * ISAL_SM3_DIGEST_NWORDS];
extern void
sm3_ossl(const unsigned char *buf, size_t length, unsigned char *digest);

// Generates pseudo-random data
static void
rand_buffer(unsigned char *buf, const long buffer_size)
{
        long i;
        for (i = 0; i < buffer_size; i++)
                buf[i] = rand();
}
#endif /* !FIPS_MODE */

int
main(void)
{
#ifndef FIPS_MODE
        ISAL_SM3_HASH_CTX_MGR *mgr = NULL;
        ISAL_SM3_HASH_CTX ctxpool[TEST_BUFS], *ctx = NULL;
        uint32_t i, j, fail = 0;
        int len_done, len_rem, len_rand;
        unsigned char *bufs[TEST_BUFS];
        unsigned char *buf_ptr[TEST_BUFS];
        uint32_t lens[TEST_BUFS];
        unsigned int joblen, jobs, t;
        int ret;

        printf("multibinary_sm3_update test, %d sets of %dx%d max: ", RANDOMS, TEST_BUFS, TEST_LEN);

        srand(TEST_SEED);

        ret = posix_memalign((void *) &mgr, 16, sizeof(ISAL_SM3_HASH_CTX_MGR));
        if ((ret != 0) || (mgr == NULL)) {
                printf("posix_memalign failed test aborted\n");
                return 1;
        }

        isal_sm3_ctx_mgr_init(mgr);

        for (i = 0; i < TEST_BUFS; i++) {
                // Allocate and fill buffer
                bufs[i] = (unsigned char *) malloc(TEST_LEN);
                buf_ptr[i] = bufs[i];
                if (bufs[i] == NULL) {
                        printf("malloc failed test aborted\n");
                        return 1;
                }
                rand_buffer(bufs[i], TEST_LEN);

                // Init ctx contents
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);

                // Run reference test
                sm3_ossl(bufs[i], TEST_LEN, digest_ref[i]);
        }

        // Run sb_sm3 tests
        for (i = 0; i < TEST_BUFS;) {
                len_done = (int) ((uintptr_t) buf_ptr[i] - (uintptr_t) bufs[i]);
                len_rem = TEST_LEN - len_done;

                int errc = 0;

                if (len_done == 0)
                        errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                       UPDATE_SIZE, ISAL_HASH_FIRST);
                else if (len_rem <= UPDATE_SIZE)
                        errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i], len_rem,
                                                       ISAL_HASH_LAST);
                else
                        errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                       UPDATE_SIZE, ISAL_HASH_UPDATE);

                // Add jobs while available or finished
                if ((errc == 0) && ((ctx == NULL) || isal_hash_ctx_complete(ctx))) {
                        i++;
                        continue;
                }
                // Resubmit unfinished job
                i = (unsigned long) (uintptr_t) (ctx->user_data);
                buf_ptr[i] += UPDATE_SIZE;
        }

        // Start flushing finished jobs, end on last flushed
        isal_sm3_ctx_mgr_flush(mgr, &ctx);

        while (ctx) {
                if (isal_hash_ctx_complete(ctx)) {
                        debug_char('-');
                        isal_sm3_ctx_mgr_flush(mgr, &ctx);
                        continue;
                }
                // Resubmit unfinished job
                i = (unsigned long) (uintptr_t) (ctx->user_data);
                buf_ptr[i] += UPDATE_SIZE;

                len_done = (int) ((uintptr_t) buf_ptr[i] - (uintptr_t) bufs[i]);
                len_rem = TEST_LEN - len_done;

                int errc = 0;

                if (len_rem <= UPDATE_SIZE)
                        errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i], len_rem,
                                                       ISAL_HASH_LAST);
                else
                        errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                       UPDATE_SIZE, ISAL_HASH_UPDATE);

                if (errc == 0 && ctx == NULL)
                        isal_sm3_ctx_mgr_flush(mgr, &ctx);
        }

        // Check digests
        for (i = 0; i < TEST_BUFS; i++) {
                for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                        if (ctxpool[i].job.result_digest[j] !=
                            to_le32(((uint32_t *) digest_ref[i])[j])) {
                                fail++;
                                printf("Test%d fixed size, digest%d fail %8X <=> %8X", i, j,
                                       ctxpool[i].job.result_digest[j],
                                       to_le32(((uint32_t *) digest_ref[i])[j]));
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
                        sm3_ossl(bufs[i], lens[i], digest_ref[i]);
                }

                isal_sm3_ctx_mgr_init(mgr);

                // Run sm3_sb jobs
                i = 0;
                while (i < jobs) {
                        // Submit a new job
                        len_rand = ISAL_SM3_BLOCK_SIZE +
                                   ISAL_SM3_BLOCK_SIZE * (rand() % MAX_RAND_UPDATE_BLOCKS);

                        int errc = 0;

                        if ((int) lens[i] > len_rand)
                                errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                               len_rand, ISAL_HASH_FIRST);
                        else
                                errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                               lens[i], ISAL_HASH_ENTIRE);

                        // Returned ctx could be:
                        //  - null context (we are just getting started and lanes aren't full yet),
                        //  or
                        //  - finished already (an ENTIRE we submitted or a previous LAST is
                        //  returned), or
                        //  - an unfinished ctx, we will resubmit

                        if ((errc == 0) && ((ctx == NULL) || isal_hash_ctx_complete(ctx))) {
                                i++;
                                continue;
                        } else {
                                // unfinished ctx returned, choose another random update length and
                                // submit either UPDATE or LAST depending on the amount of buffer
                                // remaining
                                while ((ctx != NULL) && !(isal_hash_ctx_complete(ctx))) {
                                        // Get index of the returned ctx
                                        j = (unsigned long) (uintptr_t) (ctx->user_data);
                                        buf_ptr[j] = bufs[j] + ctx->total_length;
                                        len_rand = (rand() % ISAL_SM3_BLOCK_SIZE) *
                                                   (rand() % MAX_RAND_UPDATE_BLOCKS);
                                        len_rem = (int) (lens[j] - ctx->total_length);

                                        if (len_rem <= len_rand)
                                                // submit the rest of the job as LAST
                                                errc = isal_sm3_ctx_mgr_submit(
                                                        mgr, &ctxpool[j], &ctx, buf_ptr[j], len_rem,
                                                        ISAL_HASH_LAST);
                                        else // submit the random update length as UPDATE
                                                errc = isal_sm3_ctx_mgr_submit(
                                                        mgr, &ctxpool[j], &ctx, buf_ptr[j],
                                                        len_rand, ISAL_HASH_UPDATE);
                                        if (errc)
                                                return 1;
                                } // Either continue submitting any contexts returned here as
                                  // UPDATE/LAST, or
                                // go back to submitting new jobs using the index i.

                                i++;
                        }
                }

                // Start flushing finished jobs, end on last flushed
                if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                        return 1;
                while (ctx) {
                        if (isal_hash_ctx_complete(ctx)) {
                                debug_char('-');
                                if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                                        return 1;
                                continue;
                        }
                        // Resubmit unfinished job
                        i = (unsigned long) (uintptr_t) (ctx->user_data);
                        buf_ptr[i] = bufs[i] + ctx->total_length; // update buffer pointer
                        len_rem = (int) (lens[i] - ctx->total_length);
                        len_rand =
                                (rand() % ISAL_SM3_BLOCK_SIZE) * (rand() % MAX_RAND_UPDATE_BLOCKS);
                        debug_char('+');

                        int errc = 0;

                        if (len_rem <= len_rand)
                                errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                               len_rem, ISAL_HASH_LAST);
                        else
                                errc = isal_sm3_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, buf_ptr[i],
                                                               len_rand, ISAL_HASH_UPDATE);

                        if (errc)
                                return 1;
                        if (ctx == NULL)
                                if (isal_sm3_ctx_mgr_flush(mgr, &ctx) != 0)
                                        return 1;
                }

                // Check result digest
                for (i = 0; i < jobs; i++) {
                        for (j = 0; j < ISAL_SM3_DIGEST_NWORDS; j++) {
                                if (ctxpool[i].job.result_digest[j] !=
                                    to_le32(((uint32_t *) digest_ref[i])[j])) {
                                        fail++;
                                        printf("Test%d, digest%d fail %8X <=> %8X\n", i, j,
                                               ctxpool[i].job.result_digest[j],
                                               to_le32(((uint32_t *) digest_ref[i])[j]));
                                }
                        }
                }
                if (fail) {
                        printf("Test failed function check %d\n", fail);
                        return fail;
                }

                putchar('.');
                fflush(0);
        } // random test t

        if (fail)
                printf("Test failed function check %d\n", fail);
        else
                printf(" multibinary_sm3_update rand: Pass\n");

        return fail;
#else
        printf("Not Executed\n");
        return 0;
#endif /* FIPS_MODE */
}
