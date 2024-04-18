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

#include "sha1_mb.h"

#include "internal_fips.h"
#include "types.h"
#include "test.h"

typedef uint32_t DigestSHA1[SHA1_DIGEST_NWORDS];

static const uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const DigestSHA1 expResultDigest_sha1 = { 0x84983E44, 0x1C3BD26E, 0xBAAE4AA1, 0xF95129E5,
                                                 0xE54670F1 };

static int
_sha1_self_test(void)
{

        SHA1_HASH_CTX_MGR mgr;
        SHA1_HASH_CTX ctxpool, *ctx = NULL;
        uint32_t j;

        sha1_ctx_mgr_init(&mgr);

        // Init context before first use
        hash_ctx_init(&ctxpool);

        ctx = sha1_ctx_mgr_submit(&mgr, &ctxpool, msg, strlen((char *) msg), HASH_ENTIRE);

        if (ctx == NULL)
                ctx = sha1_ctx_mgr_flush(&mgr);

        if (ctx) {
                for (j = 0; j < SHA1_DIGEST_NWORDS; j++) {
                        if (expResultDigest_sha1[j] != ctxpool.job.result_digest[j])
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

        return ret;
}
