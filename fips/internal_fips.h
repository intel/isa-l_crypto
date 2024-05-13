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

#ifndef _INTERNAL_FIPS_H
#define _INTERNAL_FIPS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Internal function checking on self tests status.
 *
 * @return  Self test result
 * @retval  0 on success, 1 on failure, else on self tests not done
 */
int
asm_check_self_tests_status(void);

/**
 * @brief Internal function setting the self tests status.
 *
 * To be called after running the self tests. It changes the status
 * to self tests OK (0) or self tests failed (1).
 *
 * @param [in] status Self test status
 */
void
asm_set_self_tests_status(int status);

/**
 * @brief Run AES self tests
 * @return  Self test result
 * @retval  0 on success, 1 on failure
 */
int
_aes_self_tests(void);

/**
 * @brief Run SHA self tests
 * @return  Self test result
 * @retval  0 on success, 1 on failure
 */
int
_sha_self_tests(void);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ifndef _INTERNAL_FIPS_H
