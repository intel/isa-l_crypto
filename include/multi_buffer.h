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

#ifndef _MULTI_BUFFER_H_
#define _MULTI_BUFFER_H_

/**
 *  @file  multi_buffer.h
 *  @brief Multi-buffer common fields
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define enums from API v2.24, so applications that were using this version
 * will still be compiled successfully.
 * This list does not need to be extended for new enums.
 */
#ifndef NO_COMPAT_ISAL_CRYPTO_API_2_24
/***** Previous enums *****/
#define JOB_STS             ISAL_JOB_STS
#define STS_UNKNOWN         ISAL_STS_UNKNOWN
#define STS_BEING_PROCESSED ISAL_STS_BEING_PROCESSED
#define STS_COMPLETED       ISAL_STS_COMPLETED
#define STS_INTERNAL_ERROR  ISAL_STS_INTERNAL_ERROR
#define STS_ERROR           ISAL_STS_ERROR

#define HASH_CTX_FLAG ISAL_HASH_CTX_FLAG
#define HASH_UPDATE   ISAL_HASH_UPDATE
#define HASH_FIRST    ISAL_HASH_FIRST
#define HASH_LAST     ISAL_HASH_LAST
#define HASH_ENTIRE   ISAL_HASH_ENTIRE

#define HASH_CTX_STS            ISAL_HASH_CTX_STS
#define HASH_CTX_STS_IDLE       ISAL_HASH_CTX_STS_IDLE
#define HASH_CTX_STS_PROCESSING ISAL_HASH_CTX_STS_PROCESSING
#define HASH_CTX_STS_LAST       ISAL_HASH_CTX_STS_LAST
#define HASH_CTX_STS_COMPLETE   ISAL_HASH_CTX_STS_COMPLETE

#define HASH_CTX_ERROR                    ISAL_HASH_CTX_ERROR
#define HASH_CTX_ERROR_NONE               ISAL_HASH_CTX_ERROR_NONE
#define HASH_CTX_ERROR_INVALID_FLAGS      ISAL_HASH_CTX_ERROR_INVALID_FLAGS
#define HASH_CTX_ERROR_ALREADY_PROCESSING ISAL_HASH_CTX_ERROR_ALREADY_PROCESSING
#define HASH_CTX_ERROR_ALREADY_COMPLETED  ISAL_HASH_CTX_ERROR_ALREADY_COMPLETED

#define HASH_MB_NO_FLAGS ISAL_HASH_MB_NO_FLAGS
#define HASH_MB_FIRST    ISAL_HASH_MB_FIRST
#define HASH_MB_LAST     ISAL_HASH_MB_LAST

#define hash_ctx_user_data  isal_hash_ctx_user_data
#define hash_ctx_digest     isal_hash_ctx_digest
#define hash_ctx_processing isal_hash_ctx_processing
#define hash_ctx_complete   isal_hash_ctx_complete
#define hash_ctx_status     isal_hash_ctx_status
#define hash_ctx_error      isal_hash_ctx_error
#define hash_ctx_init       isal_hash_ctx_init

#endif /* !NO_COMPAT_ISAL_CRYPTO_API_2_24 */

/**
 *  @enum ISAL_JOB_STS
 *  @brief Job return codes
 */

typedef enum {
        ISAL_STS_UNKNOWN = 0,         //!< ISAL_STS_UNKNOWN
        ISAL_STS_BEING_PROCESSED = 1, //!< ISAL_STS_BEING_PROCESSED
        ISAL_STS_COMPLETED = 2,       //!< ISAL_STS_COMPLETED
        ISAL_STS_INTERNAL_ERROR,      //!< ISAL_STS_INTERNAL_ERROR
        ISAL_STS_ERROR                //!< ISAL_STS_ERROR
} ISAL_JOB_STS;

#define ISAL_HASH_MB_NO_FLAGS 0
#define ISAL_HASH_MB_FIRST    1
#define ISAL_HASH_MB_LAST     2

/* Common flags for the new API only
 *  */

/**
 *  @enum ISAL_HASH_CTX_FLAG
 *  @brief CTX job type
 */
typedef enum {
        ISAL_HASH_UPDATE = 0x00, //!< ISAL_HASH_UPDATE
        ISAL_HASH_FIRST = 0x01,  //!< ISAL_HASH_FIRST
        ISAL_HASH_LAST = 0x02,   //!< ISAL_HASH_LAST
        ISAL_HASH_ENTIRE = 0x03, //!< ISAL_HASH_ENTIRE
} ISAL_HASH_CTX_FLAG;

/**
 *  @enum ISAL_HASH_CTX_STS
 *  @brief CTX status flags
 */
typedef enum {
        ISAL_HASH_CTX_STS_IDLE = 0x00,       //!< ISAL_HASH_CTX_STS_IDLE
        ISAL_HASH_CTX_STS_PROCESSING = 0x01, //!< ISAL_HASH_CTX_STS_PROCESSING
        ISAL_HASH_CTX_STS_LAST = 0x02,       //!< ISAL_HASH_CTX_STS_LAST
        ISAL_HASH_CTX_STS_COMPLETE = 0x04,   //!< ISAL_HASH_CTX_STS_COMPLETE
} ISAL_HASH_CTX_STS;

/**
 *  @enum ISAL_HASH_CTX_ERROR
 *  @brief CTX error flags
 */
typedef enum {
        ISAL_HASH_CTX_ERROR_NONE = 0,                //!< ISAL_HASH_CTX_ERROR_NONE
        ISAL_HASH_CTX_ERROR_INVALID_FLAGS = -1,      //!< ISAL_HASH_CTX_ERROR_INVALID_FLAGS
        ISAL_HASH_CTX_ERROR_ALREADY_PROCESSING = -2, //!< ISAL_HASH_CTX_ERROR_ALREADY_PROCESSING
        ISAL_HASH_CTX_ERROR_ALREADY_COMPLETED = -3,  //!< ISAL_HASH_CTX_ERROR_ALREADY_COMPLETED
} ISAL_HASH_CTX_ERROR;

#define isal_hash_ctx_user_data(ctx)  ((ctx)->user_data)
#define isal_hash_ctx_digest(ctx)     ((ctx)->job.result_digest)
#define isal_hash_ctx_processing(ctx) ((ctx)->status & ISAL_HASH_CTX_STS_PROCESSING)
#define isal_hash_ctx_complete(ctx)   ((ctx)->status == ISAL_HASH_CTX_STS_COMPLETE)
#define isal_hash_ctx_status(ctx)     ((ctx)->status)
#define isal_hash_ctx_error(ctx)      ((ctx)->error)
#define isal_hash_ctx_init(ctx)                                                                    \
        do {                                                                                       \
                (ctx)->error = ISAL_HASH_CTX_ERROR_NONE;                                           \
                (ctx)->status = ISAL_HASH_CTX_STS_COMPLETE;                                        \
        } while (0)

#ifdef __cplusplus
}
#endif

#endif // _MULTI_BUFFER_H_
