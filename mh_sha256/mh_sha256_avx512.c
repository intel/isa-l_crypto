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

#include <string.h>
#include "mh_sha256_internal.h"

#ifdef HAVE_AS_KNOWS_AVX512

/***************mh_sha256_update***********/
// mh_sha256_update_avx512.c
#define MH_SHA256_UPDATE_FUNCTION mh_sha256_update_avx512
#define MH_SHA256_BLOCK_FUNCTION  mh_sha256_block_avx512
#include "mh_sha256_update_base.c"
#undef MH_SHA256_UPDATE_FUNCTION
#undef MH_SHA256_BLOCK_FUNCTION

/***************mh_sha256_finalize AND mh_sha256_tail***********/
// mh_sha256_tail is used to calculate the last incomplete src data block
// mh_sha256_finalize is a mh_sha256_ctx wrapper of mh_sha256_tail
// mh_sha256_finalize_avx512.c and mh_sha256_tail_avx512.c
#define MH_SHA256_FINALIZE_FUNCTION mh_sha256_finalize_avx512
#define MH_SHA256_TAIL_FUNCTION     mh_sha256_tail_avx512
#define MH_SHA256_BLOCK_FUNCTION    mh_sha256_block_avx512
#include "mh_sha256_finalize_base.c"
#undef MH_SHA256_FINALIZE_FUNCTION
#undef MH_SHA256_TAIL_FUNCTION
#undef MH_SHA256_BLOCK_FUNCTION

/***************version info***********/
struct slver {
        uint16_t snum;
        uint8_t ver;
        uint8_t core;
};

// mh_sha256_update version info
struct slver mh_sha256_update_avx512_slver_060002bc;
struct slver mh_sha256_update_avx512_slver = { 0x02bc, 0x00, 0x06 };

// mh_sha256_finalize version info
struct slver mh_sha256_finalize_avx512_slver_060002bd;
struct slver mh_sha256_finalize_avx512_slver = { 0x02bd, 0x00, 0x06 };

#endif // HAVE_AS_KNOWS_AVX512
