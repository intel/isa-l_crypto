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

#include "isal_crypto_api.h"
#include "internal_fips.h"

#ifndef likely
#if defined(__unix__) || (__APPLE__) || (__MINGW32__)
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (!!(x))
#endif
#endif /* likely */

int
isal_self_tests(void)
{
#ifdef FIPS_MODE
        int ret = asm_check_self_tests_status();

        if (likely(ret == 0))
                return 0;
        else if (ret == 1)
                return ISAL_CRYPTO_ERR_SELF_TEST;

        /* Self tests have not been done yet, so run them */
        ret = _aes_self_tests();

        ret |= _sha_self_tests();

        asm_set_self_tests_status(ret);

        if (ret == 0)
                return 0;
        else
                return ISAL_CRYPTO_ERR_SELF_TEST;
#else  /* FIPS_MODE disabled */
        return ISAL_CRYPTO_ERR_FIPS_DISABLED;
#endif /* FIPS_MODE */
}
