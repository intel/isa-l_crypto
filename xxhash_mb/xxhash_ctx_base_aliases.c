/**********************************************************************
  Copyright(c) 2022 Linaro Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Linaro Corporation nor the names of its
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

#include <string.h>
#include "xxhash_mb.h"

extern void
xxh32_ctx_mgr_init_base(XXH32_HASH_CTX_MGR *mgr);
extern XXH32_HASH_CTX *
xxh32_ctx_mgr_flush_base(XXH32_HASH_CTX_MGR *mgr);
extern XXH32_HASH_CTX *
xxh32_ctx_mgr_submit_base(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx, const void *buffer,
                          uint32_t len, HASH_CTX_FLAG flags);

extern void
xxh64_ctx_mgr_init_base(XXH64_HASH_CTX_MGR *mgr);
extern XXH64_HASH_CTX *
xxh64_ctx_mgr_flush_base(XXH64_HASH_CTX_MGR *mgr);
extern XXH64_HASH_CTX *
xxh64_ctx_mgr_submit_base(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx, const void *buffer,
                          uint64_t len, HASH_CTX_FLAG flags);

void
xxh32_ctx_mgr_init(XXH32_HASH_CTX_MGR *mgr)
{
        xxh32_ctx_mgr_init_base(mgr);
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_flush(XXH32_HASH_CTX_MGR *mgr)
{
        return xxh32_ctx_mgr_flush_base(mgr);
}

XXH32_HASH_CTX *
xxh32_ctx_mgr_submit(XXH32_HASH_CTX_MGR *mgr, XXH32_HASH_CTX *ctx, const void *buffer, uint32_t len,
                     HASH_CTX_FLAG flags)
{
        return xxh32_ctx_mgr_submit_base(mgr, ctx, buffer, len, flags);
}

void
xxh64_ctx_mgr_init(XXH64_HASH_CTX_MGR *mgr)
{
        xxh64_ctx_mgr_init_base(mgr);
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_flush(XXH64_HASH_CTX_MGR *mgr)
{
        return xxh64_ctx_mgr_flush_base(mgr);
}

XXH64_HASH_CTX *
xxh64_ctx_mgr_submit(XXH64_HASH_CTX_MGR *mgr, XXH64_HASH_CTX *ctx, const void *buffer, uint64_t len,
                     HASH_CTX_FLAG flags)
{
        return xxh64_ctx_mgr_submit_base(mgr, ctx, buffer, len, flags);
}
