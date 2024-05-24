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
#include "md5_mb.h"

#ifndef FIPS_MODE
typedef uint32_t DigestMD5[ISAL_MD5_DIGEST_NWORDS];

#define MSGS     13
#define NUM_JOBS 1000

#define PSEUDO_RANDOM_NUM(seed) ((seed) * 5 + ((seed) * (seed)) / 64) % MSGS

static uint8_t msg1[] = "Test vector from febooti.com";
static uint8_t msg2[] = "12345678901234567890"
                        "12345678901234567890"
                        "12345678901234567890"
                        "12345678901234567890";
static uint8_t msg3[] = "";
static uint8_t msg4[] = "abcdefghijklmnopqrstuvwxyz";
static uint8_t msg5[] = "message digest";
static uint8_t msg6[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz0123456789";
static uint8_t msg7[] = "abc";
static uint8_t msg8[] = "a";

static uint8_t msg9[] = "";
static uint8_t msgA[] = "abcdefghijklmnopqrstuvwxyz";
static uint8_t msgB[] = "message digest";
static uint8_t msgC[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz0123456789";
static uint8_t msgD[] = "abc";

static DigestMD5 expResultDigest1 = { 0x61b60a50, 0xfbb76d3c, 0xf5620cd3, 0x0f3d57ff };
static DigestMD5 expResultDigest2 = { 0xa2f4ed57, 0x55c9e32b, 0x2eda49ac, 0x7ab60721 };
static DigestMD5 expResultDigest3 = { 0xd98c1dd4, 0x04b2008f, 0x980980e9, 0x7e42f8ec };
static DigestMD5 expResultDigest4 = { 0xd7d3fcc3, 0x00e49261, 0x6c49fb7d, 0x3be167ca };
static DigestMD5 expResultDigest5 = { 0x7d696bf9, 0x8d93b77c, 0x312f5a52, 0xd061f1aa };
static DigestMD5 expResultDigest6 = { 0x98ab74d1, 0xf5d977d2, 0x2c1c61a5, 0x9f9d419f };
static DigestMD5 expResultDigest7 = { 0x98500190, 0xb04fd23c, 0x7d3f96d6, 0x727fe128 };
static DigestMD5 expResultDigest8 = { 0xb975c10c, 0xa8b6f1c0, 0xe299c331, 0x61267769 };

static DigestMD5 expResultDigest9 = { 0xd98c1dd4, 0x04b2008f, 0x980980e9, 0x7e42f8ec };
static DigestMD5 expResultDigestA = { 0xd7d3fcc3, 0x00e49261, 0x6c49fb7d, 0x3be167ca };
static DigestMD5 expResultDigestB = { 0x7d696bf9, 0x8d93b77c, 0x312f5a52, 0xd061f1aa };
static DigestMD5 expResultDigestC = { 0x98ab74d1, 0xf5d977d2, 0x2c1c61a5, 0x9f9d419f };
static DigestMD5 expResultDigestD = { 0x98500190, 0xb04fd23c, 0x7d3f96d6, 0x727fe128 };

static uint8_t *msgs[MSGS] = { msg1, msg2, msg3, msg4, msg5, msg6, msg7,
                               msg8, msg9, msgA, msgB, msgC, msgD };

static uint32_t *expResultDigest[MSGS] = { expResultDigest1, expResultDigest2, expResultDigest3,
                                           expResultDigest4, expResultDigest5, expResultDigest6,
                                           expResultDigest7, expResultDigest8, expResultDigest9,
                                           expResultDigestA, expResultDigestB, expResultDigestC,
                                           expResultDigestD };

#define NUM_CHUNKS   4
#define DATA_BUF_LEN 4096
int
non_blocksize_updates_test(ISAL_MD5_HASH_CTX_MGR *mgr)
{
        ISAL_MD5_HASH_CTX ctx_refer;
        ISAL_MD5_HASH_CTX ctx_pool[NUM_CHUNKS];
        ISAL_MD5_HASH_CTX *ctx = NULL;
        int rc;

        const int update_chunks[NUM_CHUNKS] = { 32, 64, 128, 256 };
        unsigned char data_buf[DATA_BUF_LEN];

        memset(data_buf, 0xA, DATA_BUF_LEN);

        // Init contexts before first use
        isal_hash_ctx_init(&ctx_refer);

        rc = isal_md5_ctx_mgr_submit(mgr, &ctx_refer, &ctx, data_buf, DATA_BUF_LEN,
                                     ISAL_HASH_ENTIRE);
        if (rc)
                return -1;

        rc = isal_md5_ctx_mgr_flush(mgr, &ctx);
        if (rc)
                return -1;

        for (int c = 0; c < NUM_CHUNKS; c++) {
                int chunk = update_chunks[c];
                isal_hash_ctx_init(&ctx_pool[c]);
                rc = isal_md5_ctx_mgr_submit(mgr, &ctx_pool[c], &ctx, NULL, 0, ISAL_HASH_FIRST);
                if (rc)
                        return -1;
                rc = isal_md5_ctx_mgr_flush(mgr, &ctx);
                if (rc)
                        return -1;
                for (int i = 0; i * chunk < DATA_BUF_LEN; i++) {
                        rc = isal_md5_ctx_mgr_submit(mgr, &ctx_pool[c], &ctx, data_buf + i * chunk,
                                                     chunk, ISAL_HASH_UPDATE);
                        if (rc)
                                return -1;
                        rc = isal_md5_ctx_mgr_flush(mgr, &ctx);
                        if (rc)
                                return -1;
                }
        }

        for (int c = 0; c < NUM_CHUNKS; c++) {
                rc = isal_md5_ctx_mgr_submit(mgr, &ctx_pool[c], &ctx, NULL, 0, ISAL_HASH_LAST);
                if (rc)
                        return -1;
                rc = isal_md5_ctx_mgr_flush(mgr, &ctx);
                if (rc)
                        return -1;
                if (ctx_pool[c].status != ISAL_HASH_CTX_STS_COMPLETE) {
                        return -1;
                }
                for (int i = 0; i < ISAL_MD5_DIGEST_NWORDS; i++) {
                        if (ctx_refer.job.result_digest[i] != ctx_pool[c].job.result_digest[i]) {
                                printf("md5 calc error! chunk %d, digest[%d], (%d) != (%d)\n",
                                       update_chunks[c], i, ctx_refer.job.result_digest[i],
                                       ctx_pool[c].job.result_digest[i]);
                                return -2;
                        }
                }
        }
        return 0;
}
#endif

int
main(void)
{
#ifndef FIPS_MODE
        ISAL_MD5_HASH_CTX_MGR *mgr = NULL;
        ISAL_MD5_HASH_CTX ctxpool[NUM_JOBS], *ctx = NULL;
        uint32_t i, j, k, t, checked = 0;
        uint32_t *good;
        int rc, ret = -1;

        rc = posix_memalign((void *) &mgr, 16, sizeof(ISAL_MD5_HASH_CTX_MGR));
        if ((rc != 0) || (mgr == NULL)) {
                printf("posix_memalign failed test aborted\n");
                return 1;
        }

        rc = isal_md5_ctx_mgr_init(mgr);
        if (rc)
                goto end;

        // Init contexts before first use
        for (i = 0; i < MSGS; i++) {
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);
        }

        for (i = 0; i < MSGS; i++) {
                rc = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, msgs[i],
                                             (uint32_t) strlen((char *) msgs[i]), ISAL_HASH_ENTIRE);
                if (rc)
                        goto end;

                if (ctx) {
                        t = (uint32_t) (uintptr_t) (ctx->user_data);
                        good = expResultDigest[t];
                        checked++;
                        for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }

                        if (ctx->error) {
                                printf("Something bad happened during the submit."
                                       " Error code: %d",
                                       ctx->error);
                                goto end;
                        }
                }
        }

        while (1) {
                rc = isal_md5_ctx_mgr_flush(mgr, &ctx);
                if (rc)
                        goto end;

                if (ctx) {
                        t = (uint32_t) (uintptr_t) (ctx->user_data);
                        good = expResultDigest[t];
                        checked++;
                        for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }

                        if (ctx->error) {
                                printf("Something bad happened during the submit."
                                       " Error code: %d",
                                       ctx->error);
                                goto end;
                        }
                } else {
                        break;
                }
        }

        // do larger test in pseudo-random order

        // Init contexts before first use
        for (i = 0; i < NUM_JOBS; i++) {
                isal_hash_ctx_init(&ctxpool[i]);
                ctxpool[i].user_data = (void *) ((uint64_t) i);
        }

        checked = 0;
        for (i = 0; i < NUM_JOBS; i++) {
                j = PSEUDO_RANDOM_NUM(i);
                rc = isal_md5_ctx_mgr_submit(mgr, &ctxpool[i], &ctx, msgs[j],
                                             (uint32_t) strlen((char *) msgs[j]), ISAL_HASH_ENTIRE);
                if (rc)
                        goto end;
                if (ctx) {
                        t = (uint32_t) (uintptr_t) (ctx->user_data);
                        k = PSEUDO_RANDOM_NUM(t);
                        good = expResultDigest[k];
                        checked++;
                        for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }

                        if (ctx->error) {
                                printf("Something bad happened during the"
                                       " submit. Error code: %d",
                                       ctx->error);
                                goto end;
                        }

                        t = (uint32_t) (uintptr_t) (ctx->user_data);
                        k = PSEUDO_RANDOM_NUM(t);
                }
        }
        while (1) {
                rc = isal_md5_ctx_mgr_flush(mgr, &ctx);

                if (rc)
                        goto end;

                if (ctx) {
                        t = (uint32_t) (uintptr_t) (ctx->user_data);
                        k = PSEUDO_RANDOM_NUM(t);
                        good = expResultDigest[k];
                        checked++;
                        for (j = 0; j < ISAL_MD5_DIGEST_NWORDS; j++) {
                                if (good[j] != ctxpool[t].job.result_digest[j]) {
                                        printf("Test %d, digest %d is %08X, should be %08X\n", t, j,
                                               ctxpool[t].job.result_digest[j], good[j]);
                                        goto end;
                                }
                        }

                        if (ctx->error) {
                                printf("Something bad happened during the submit."
                                       " Error code: %d",
                                       ctx->error);
                                goto end;
                        }
                } else {
                        break;
                }
        }

        if (checked != NUM_JOBS) {
                printf("only tested %d rather than %d\n", checked, NUM_JOBS);
                goto end;
        }

        rc = non_blocksize_updates_test(mgr);
        if (rc) {
                printf("multi updates test fail %d\n", ret);
                goto end;
        }
        ret = 0;

        printf(" multibinary_md5 test: Pass\n");
end:
        aligned_free(mgr);

        return ret;
#else
        printf("Not Executed\n");

        return 0;
#endif /* FIPS_MODE */
}
