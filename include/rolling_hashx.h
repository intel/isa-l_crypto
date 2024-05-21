/**********************************************************************
  Copyright(c) 2011-2017 Intel Corporation All rights reserved.

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

/**
 *  @file  rolling_hashx.h
 *  @brief Fingerprint functions based on rolling hash
 *
 *  rolling_hash2 - checks hash in a sliding window based on random 64-bit hash.
 */

#ifndef _ROLLING_HASHX_H_
#define _ROLLING_HASHX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "types.h"

/*
 * Define enums from API v2.24, so applications that were using this version
 * will still be compiled successfully.
 * This list does not need to be extended for new definitions.
 */
#ifndef NO_COMPAT_ISAL_CRYPTO_API_2_24
/***** Previous hash constants and typedefs *****/
#define FINGERPRINT_RET_HIT   ISAL_FINGERPRINT_RET_HIT
#define FINGERPRINT_RET_MAX   ISAL_FINGERPRINT_RET_MAX
#define FINGERPRINT_RET_OTHER ISAL_FINGERPRINT_RET_OTHER

#define FINGERPRINT_MAX_WINDOW ISAL_FINGERPRINT_MAX_WINDOW

#define rh_state2 isal_rh_state2
#endif /* !NO_COMPAT_ISAL_CRYPTO_API_2_24 */

/**
 *@brief rolling hash return values
 */
enum {
        ISAL_FINGERPRINT_RET_HIT = 0, //!< Fingerprint trigger hit
        ISAL_FINGERPRINT_RET_MAX,     //!< Fingerprint max length reached before hit
        ISAL_FINGERPRINT_RET_OTHER    //!< Fingerprint function error returned
};

#define ISAL_FINGERPRINT_MAX_WINDOW 48

/**
 * @brief Context for rolling_hash2 functions
 */
struct isal_rh_state2 {
        uint8_t history[ISAL_FINGERPRINT_MAX_WINDOW];
        uint64_t table1[256];
        uint64_t table2[256];
        uint64_t hash;
        uint32_t w;
};

/**
 * @brief Initialize state object for rolling hash2
 *
 * @param state Structure holding state info on current rolling hash
 * @param w     Window width (1 <= w <= 32)
 * @returns 0 - success, -1 - failure
 * @deprecated Please use isal_rolling_hash2_init() instead.
 */
ISAL_DEPRECATED("Please use isal_rolling_hash2_init() instead")
int
rolling_hash2_init(struct isal_rh_state2 *state, uint32_t w);

/**
 * @brief Reset the hash state history
 *
 * @param state Structure holding state info on current rolling hash
 * @param init_bytes Optional window size buffer to pre-init hash
 * @returns none
 * @deprecated Please use isal_rolling_hash2_reset() instead.
 */
ISAL_DEPRECATED("Please use isal_rolling_hash2_reset() instead")
void
rolling_hash2_reset(struct isal_rh_state2 *state, uint8_t *init_bytes);

/**
 * @brief Run rolling hash function until trigger met or max length reached
 *
 * Checks for trigger based on a random hash in a sliding window.
 * @param state   Structure holding state info on current rolling hash
 * @param buffer  Pointer to input buffer to run windowed hash on
 * @param max_len Max length to run over input
 * @param mask    Mask bits ORed with hash before test with trigger
 * @param trigger Match value to compare with windowed hash at each input byte
 * @param offset  Offset from buffer to match, set if match found
 * @returns ISAL_FINGERPRINT_RET_HIT - match found, ISAL_FINGERPRINT_RET_MAX - exceeded max length
 * @deprecated Please use isal_rolling_hash2_run() instead.
 */
ISAL_DEPRECATED("Please use isal_rolling_hash2_run() instead")
int
rolling_hash2_run(struct isal_rh_state2 *state, uint8_t *buffer, uint32_t max_len, uint32_t mask,
                  uint32_t trigger, uint32_t *offset);

/**
 * @brief Generate an appropriate mask to target mean hit rate
 *
 * @param mean  Target chunk size in bytes
 * @param shift Bits to rotate result to get independent masks
 * @returns 32-bit mask value
 * @deprecated Please use isal_rolling_hashx_mask_gen() instead.
 */
ISAL_DEPRECATED("Please use isal_rolling_hashx_mask_gen() instead")
uint32_t
rolling_hashx_mask_gen(long mean, int shift);

/**
 * @brief Initialize state object for rolling hash2
 *
 * @param[in] state Structure holding state info on current rolling hash
 * @param[in] w Window width (1 <= w <= 32)
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_rolling_hash2_init(struct isal_rh_state2 *state, const uint32_t w);

/**
 * @brief Reset the hash state history
 *
 * @param[in] state Structure holding state info on current rolling hash
 * @param[in] init_bytes Optional window size buffer to pre-init hash
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_rolling_hash2_reset(struct isal_rh_state2 *state, const uint8_t *init_bytes);

/**
 * @brief Run rolling hash function until trigger met or max length reached
 *
 * Checks for trigger based on a random hash in a sliding window.
 * @param[in] state Structure holding state info on current rolling hash
 * @param[in] buffer Pointer to input buffer to run windowed hash on
 * @param[in] max_len Max length to run over input
 * @param[in] mask Mask bits ORed with hash before test with trigger
 * @param[in] trigger Match value to compare with windowed hash at each input byte
 * @param[out] offset Offset from buffer to match, set if match found
 * @param[out] match Pointer to fingerprint result status to set
 *                   ISAL_FINGERPRINT_RET_HIT - match found
 *                   ISAL_FINGERPRINT_RET_MAX - exceeded max length
 *                   ISAL_FINGERPRINT_RET_OTHER - error
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_rolling_hash2_run(struct isal_rh_state2 *state, const uint8_t *buffer, const uint32_t max_len,
                       const uint32_t mask, const uint32_t trigger, uint32_t *offset, int *match);

/**
 * @brief Generate an appropriate mask to target mean hit rate
 *
 * @param[in] mean Target chunk size in bytes
 * @param[in] shift Bits to rotate result to get independent masks
 * @param[out] mask Generated 32-bit mask value
 * @return Operation status
 * @retval 0 on success
 * @retval Non-zero \a ISAL_CRYPTO_ERR on failure
 */
int
isal_rolling_hashx_mask_gen(const uint32_t mean, const uint32_t shift, uint32_t *mask);

#ifdef __cplusplus
}
#endif

#endif // _ROLLING_HASHX_H_
