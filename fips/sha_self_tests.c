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

/*
 * SHA self tests
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha1_mb_internal.h"
#include "sha256_mb.h"
#include "sha512_mb.h"

#include "internal_fips.h"
#include "types.h"
#include "test.h"

typedef uint32_t DigestSHA1[SHA1_DIGEST_NWORDS];
typedef uint32_t DigestSHA256[SHA256_DIGEST_NWORDS];
typedef uint64_t DigestSHA512[SHA512_DIGEST_NWORDS];

static const uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const DigestSHA1 expResultDigest_sha1 = { 0x84983E44, 0x1C3BD26E, 0xBAAE4AA1, 0xF95129E5,
                                                 0xE54670F1 };

static const DigestSHA256 expResultDigest_sha256 = {
        0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039,
        0xA33CE459, 0x64FF2167, 0xF6ECEDD4, 0x19DB06C1
};

static uint8_t msg_sha512[] = "The quick brown fox jumps over the lazy dog";
static DigestSHA512 expResultDigest_sha512 = { 0x07e547d9586f6a73, 0xf73fbac0435ed769,
                                               0x51218fb7d0c8d788, 0xa309d785436bbb64,
                                               0x2e93a252a954f239, 0x12547d1e8a3b5ed6,
                                               0xe1bfd7097821233f, 0xa0538f3db854fee6 };

static int
_sha1_self_test(void)
{

        SHA1_HASH_CTX_MGR mgr;
        SHA1_HASH_CTX ctxpool, *ctx = NULL;
        uint32_t j;

        _sha1_ctx_mgr_init(&mgr);

        // Init context before first use
        hash_ctx_init(&ctxpool);

        ctx = _sha1_ctx_mgr_submit(&mgr, &ctxpool, msg, (uint32_t) strlen((char *) msg),
                                   HASH_ENTIRE);

        if (ctx == NULL)
                ctx = _sha1_ctx_mgr_flush(&mgr);

        if (ctx) {
                for (j = 0; j < SHA1_DIGEST_NWORDS; j++) {
                        if (expResultDigest_sha1[j] != ctxpool.job.result_digest[j])
                                return -1;
                }
        } else
                return -1;

        return 0;
}

static int
_sha256_self_test(void)
{

        SHA256_HASH_CTX_MGR mgr;
        SHA256_HASH_CTX ctxpool, *ctx = NULL;
        uint32_t j;

        sha256_ctx_mgr_init(&mgr);

        // Init context before first use
        hash_ctx_init(&ctxpool);

        ctx = sha256_ctx_mgr_submit(&mgr, &ctxpool, msg, (uint32_t) strlen((char *) msg),
                                    HASH_ENTIRE);

        if (ctx == NULL)
                ctx = sha256_ctx_mgr_flush(&mgr);

        if (ctx) {
                for (j = 0; j < SHA256_DIGEST_NWORDS; j++) {
                        if (expResultDigest_sha256[j] != ctxpool.job.result_digest[j])
                                return -1;
                }
        } else
                return -1;

        return 0;
}

static int
_sha512_self_test(void)
{

        SHA512_HASH_CTX_MGR mgr;
        SHA512_HASH_CTX ctxpool, *ctx = NULL;
        uint32_t j;

        sha512_ctx_mgr_init(&mgr);

        // Init context before first use
        hash_ctx_init(&ctxpool);

        ctx = sha512_ctx_mgr_submit(&mgr, &ctxpool, msg_sha512,
                                    (uint32_t) strlen((char *) msg_sha512), HASH_ENTIRE);

        if (ctx == NULL)
                ctx = sha512_ctx_mgr_flush(&mgr);

        if (ctx) {
                for (j = 0; j < SHA512_DIGEST_NWORDS; j++) {
                        if (expResultDigest_sha512[j] != ctxpool.job.result_digest[j])
                                return -1;
                }
        } else
                return -1;

        return 0;
}

int
_sha_self_tests(void)
{
        int ret;

        ret = _sha1_self_test();
        ret |= _sha256_self_test();
        ret |= _sha512_self_test();

        return ret;
}
