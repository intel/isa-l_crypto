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

#ifdef FIPS_MODE
#include <stdatomic.h>
#include <unistd.h>
#define SLEEP(x) usleep(x)
#define TIME     1 // 1 microsecond

#define SELF_TEST_DONE_AND_OK   0
#define SELF_TEST_DONE_AND_FAIL 1
#define SELF_TEST_NOT_DONE      2
#define SELF_TEST_RUNNING       3
#endif /* FIPS_MODE */

int
isal_self_tests(void)
{
#ifdef FIPS_MODE
        static atomic_int self_tests_status = SELF_TEST_NOT_DONE;
        int self_tests_not_done = SELF_TEST_NOT_DONE;

        if (atomic_load(&self_tests_status) == SELF_TEST_DONE_AND_OK)
                return 0;

        if (atomic_load(&self_tests_status) == SELF_TEST_DONE_AND_FAIL)
                return ISAL_CRYPTO_ERR_SELF_TEST;

        if (atomic_compare_exchange_strong(&self_tests_status, &self_tests_not_done,
                                           SELF_TEST_RUNNING)) {
                if (_aes_self_tests() != 0) {
                        atomic_store(&self_tests_status, SELF_TEST_DONE_AND_FAIL);
                        return ISAL_CRYPTO_ERR_SELF_TEST;
                }
                if (_sha_self_tests() != 0) {
                        atomic_store(&self_tests_status, SELF_TEST_DONE_AND_FAIL);
                        return ISAL_CRYPTO_ERR_SELF_TEST;
                }
                atomic_store(&self_tests_status, SELF_TEST_DONE_AND_OK);

                return 0;
        } else {
                /* At this stage, only a thread that encountered SELF_TEST_RUNNING reaches here */
                while (atomic_load(&self_tests_status) == SELF_TEST_RUNNING)
                        SLEEP(TIME);

                /* After waiting for the status to change from "SELF_TEST_RUNNING",
                 * read the self test status and return success or failure */
                if (self_tests_status == SELF_TEST_DONE_AND_OK)
                        return 0;
                else
                        return ISAL_CRYPTO_ERR_SELF_TEST;
        }
#else  /* FIPS_MODE disabled */
        return ISAL_CRYPTO_ERR_FIPS_DISABLED;
#endif /* FIPS_MODE */
}
