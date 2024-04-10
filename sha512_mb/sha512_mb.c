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

#include "sha512_mb.h"
#include "isal_crypto_api.h"
#include "multi_buffer.h"

int isal_sha512_ctx_mgr_init(SHA512_HASH_CTX_MGR * mgr)
{
#ifdef SAFE_PARAM
	if (mgr == NULL)
		return ISAL_CRYPTO_ERR_NULL_MGR;
#endif
	sha512_ctx_mgr_init(mgr);

	return 0;
}

int isal_sha512_ctx_mgr_submit(SHA512_HASH_CTX_MGR * mgr, SHA512_HASH_CTX * ctx_in,
			       SHA512_HASH_CTX ** ctx_out, const void *buffer,
			       const uint32_t len, const HASH_CTX_FLAG flags)
{
#ifdef SAFE_PARAM
	if (mgr == NULL)
		return ISAL_CRYPTO_ERR_NULL_MGR;
	if (ctx_in == NULL || ctx_out == NULL)
		return ISAL_CRYPTO_ERR_NULL_CTX;
	if (buffer == NULL)
		return ISAL_CRYPTO_ERR_NULL_SRC;
#endif

	*ctx_out = sha512_ctx_mgr_submit(mgr, ctx_in, buffer, len, flags);

#ifdef SAFE_PARAM
	if (*ctx_out != NULL && (SHA512_HASH_CTX *) (*ctx_out)->error != HASH_CTX_ERROR_NONE) {
		SHA512_HASH_CTX *cp = (SHA512_HASH_CTX *) (*ctx_out);

		if (cp->error == HASH_CTX_ERROR_INVALID_FLAGS)
			return ISAL_CRYPTO_ERR_INVALID_FLAGS;
		if (cp->error == HASH_CTX_ERROR_ALREADY_PROCESSING)
			return ISAL_CRYPTO_ERR_ALREADY_PROCESSING;
		if (cp->error == HASH_CTX_ERROR_ALREADY_COMPLETED)
			return ISAL_CRYPTO_ERR_ALREADY_COMPLETED;
	}
#endif
	return 0;
}

int isal_sha512_ctx_mgr_flush(SHA512_HASH_CTX_MGR * mgr, SHA512_HASH_CTX ** ctx_out)
{
#ifdef SAFE_PARAM
	if (mgr == NULL)
		return ISAL_CRYPTO_ERR_NULL_MGR;
	if (ctx_out == NULL)
		return ISAL_CRYPTO_ERR_NULL_CTX;
#endif

	*ctx_out = sha512_ctx_mgr_flush(mgr);

	return 0;
}
