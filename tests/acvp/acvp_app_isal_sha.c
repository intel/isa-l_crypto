/**********************************************************************
  Copyright(c) 2022, Intel Corporation All rights reserved.

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
#include <acvp/acvp.h>
#include <isa-l_crypto.h>

extern uint8_t verbose;

#define LARGEST_TEST_MSG (1ul << 31)

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                                    \
        __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_be32(x)
#define to_be64(x)
#else
#define to_be32(x) (((x) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | ((x) >> 24))
#define to_be64(x)                                                                                 \
        ((((x) & (0xffull << 0)) << 56) | (((x) & (0xffull << 8)) << 40) |                         \
         (((x) & (0xffull << 16)) << 24) | (((x) & (0xffull << 24)) << 8) |                        \
         (((x) & (0xffull << 32)) >> 8) | (((x) & (0xffull << 40)) >> 24) |                        \
         (((x) & (0xffull << 48)) >> 40) | (((x) & (0xffull << 56)) >> 56))

#endif

inline void static md_dcpy(void *bdst, uint32_t *dsrc, int dwords)
{
        int i;
        uint32_t *ddst = (uint32_t *) bdst;
        for (i = 0; i < dwords; i++)
                ddst[i] = to_be32(dsrc[i]);
}

inline void static md_qcpy(void *bdst, uint64_t *qsrc, int qwords)
{
        int i;
        uint64_t *qdst = (uint64_t *) bdst;
        for (i = 0; i < qwords; i++)
                qdst[i] = to_be64(qsrc[i]);
}

static int
sha_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_RESULT ret = ACVP_SUCCESS;
        ACVP_HASH_TC *tc;
        int rc;

        if (verbose > 2)
                printf("sha case\n");

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.hash;
        if (!tc)
                return EXIT_FAILURE;

        if (!tc->msg)
                return EXIT_FAILURE;

        switch (acvp_get_hash_alg(tc->cipher)) {
        case ACVP_SUB_HASH_SHA1: {
                ISAL_SHA1_HASH_CTX_MGR sha1_mgr;
                ISAL_SHA1_HASH_CTX sha1_ctx, *ctx = NULL;
                rc = isal_sha1_ctx_mgr_init(&sha1_mgr);
                if (rc)
                        return EXIT_FAILURE;
                isal_hash_ctx_init(&sha1_ctx);
                if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                        rc = isal_sha1_ctx_mgr_submit(&sha1_mgr, &sha1_ctx, &ctx, tc->m1,
                                                      tc->msg_len, ISAL_HASH_FIRST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha1_ctx_mgr_flush(&sha1_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha1_ctx_mgr_submit(&sha1_mgr, &sha1_ctx, &ctx, tc->m2,
                                                      tc->msg_len, ISAL_HASH_UPDATE);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha1_ctx_mgr_flush(&sha1_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha1_ctx_mgr_submit(&sha1_mgr, &sha1_ctx, &ctx, tc->m3,
                                                      tc->msg_len, ISAL_HASH_LAST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha1_ctx_mgr_flush(&sha1_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                } else {
                        rc = isal_sha1_ctx_mgr_submit(&sha1_mgr, &sha1_ctx, &ctx, tc->msg,
                                                      tc->msg_len, ISAL_HASH_ENTIRE);
                        if (rc)
                                return EXIT_FAILURE;

                        if (ctx == NULL) {
                                rc = isal_sha1_ctx_mgr_flush(&sha1_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }
                }
                md_dcpy(tc->md, sha1_ctx.job.result_digest, ISAL_SHA1_DIGEST_NWORDS);
                tc->md_len = ISAL_SHA1_DIGEST_NWORDS * 4;

                break;
        }
        case ACVP_SUB_HASH_SHA2_256: {
                ISAL_SHA256_HASH_CTX_MGR sha256_mgr;
                ISAL_SHA256_HASH_CTX sha256_ctx, *ctx = NULL;
                rc = isal_sha256_ctx_mgr_init(&sha256_mgr);
                if (rc)
                        return EXIT_FAILURE;
                isal_hash_ctx_init(&sha256_ctx);
                if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                        rc = isal_sha256_ctx_mgr_submit(&sha256_mgr, &sha256_ctx, &ctx, tc->m1,
                                                        tc->msg_len, ISAL_HASH_FIRST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha256_ctx_mgr_flush(&sha256_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha256_ctx_mgr_submit(&sha256_mgr, &sha256_ctx, &ctx, tc->m2,
                                                        tc->msg_len, ISAL_HASH_UPDATE);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha256_ctx_mgr_flush(&sha256_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha256_ctx_mgr_submit(&sha256_mgr, &sha256_ctx, &ctx, tc->m3,
                                                        tc->msg_len, ISAL_HASH_LAST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha256_ctx_mgr_flush(&sha256_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                } else {
                        rc = isal_sha256_ctx_mgr_submit(&sha256_mgr, &sha256_ctx, &ctx, tc->msg,
                                                        tc->msg_len, ISAL_HASH_ENTIRE);
                        if (rc)
                                return EXIT_FAILURE;

                        if (ctx == NULL) {
                                rc = isal_sha256_ctx_mgr_flush(&sha256_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }
                }
                md_dcpy(tc->md, sha256_ctx.job.result_digest, ISAL_SHA256_DIGEST_NWORDS);
                tc->md_len = ISAL_SHA256_DIGEST_NWORDS * 4;
                break;
        }
        case ACVP_SUB_HASH_SHA2_512: {
                ISAL_SHA512_HASH_CTX_MGR sha512_mgr;
                ISAL_SHA512_HASH_CTX sha512_ctx, *ctx = NULL;
                rc = isal_sha512_ctx_mgr_init(&sha512_mgr);
                if (rc)
                        return EXIT_FAILURE;
                isal_hash_ctx_init(&sha512_ctx);
                if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
                        rc = isal_sha512_ctx_mgr_submit(&sha512_mgr, &sha512_ctx, &ctx, tc->m1,
                                                        tc->msg_len, ISAL_HASH_FIRST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha512_ctx_mgr_flush(&sha512_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha512_ctx_mgr_submit(&sha512_mgr, &sha512_ctx, &ctx, tc->m2,
                                                        tc->msg_len, ISAL_HASH_UPDATE);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha512_ctx_mgr_flush(&sha512_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                        rc = isal_sha512_ctx_mgr_submit(&sha512_mgr, &sha512_ctx, &ctx, tc->m3,
                                                        tc->msg_len, ISAL_HASH_LAST);
                        if (rc)
                                return EXIT_FAILURE;
                        if (ctx == NULL) {
                                rc = isal_sha512_ctx_mgr_flush(&sha512_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }

                } else {
                        rc = isal_sha512_ctx_mgr_submit(&sha512_mgr, &sha512_ctx, &ctx, tc->msg,
                                                        tc->msg_len, ISAL_HASH_ENTIRE);
                        if (rc)
                                return EXIT_FAILURE;

                        if (ctx == NULL) {
                                rc = isal_sha512_ctx_mgr_flush(&sha512_mgr, &ctx);
                                if (rc)
                                        return EXIT_FAILURE;
                        }
                }
                md_qcpy(tc->md, sha512_ctx.job.result_digest, ISAL_SHA512_DIGEST_NWORDS);
                tc->md_len = ISAL_SHA256_DIGEST_NWORDS * 8;
                break;
        }
        default:
                return ACVP_NO_CAP;
        }

        return ret;
}

int
enable_sha(ACVP_CTX *ctx)
{
        ACVP_RESULT ret = ACVP_SUCCESS;

        if (verbose)
                printf(" Enable isa-l_crypto sha\n");

        ret = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &sha_handler);
        ret |= acvp_cap_hash_enable(ctx, ACVP_HASH_SHA256, &sha_handler);
        ret |= acvp_cap_hash_enable(ctx, ACVP_HASH_SHA512, &sha_handler);
        if (ret != ACVP_SUCCESS)
                goto exit;

        ret |= acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA1, ACVP_HASH_MESSAGE_LEN, 0,
                                        LARGEST_TEST_MSG, 8);

        ret |= acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA256, ACVP_HASH_MESSAGE_LEN, 0,
                                        LARGEST_TEST_MSG, 8);

        ret |= acvp_cap_hash_set_domain(ctx, ACVP_HASH_SHA512, ACVP_HASH_MESSAGE_LEN, 0,
                                        LARGEST_TEST_MSG, 8);

exit:
        return ret;
}
