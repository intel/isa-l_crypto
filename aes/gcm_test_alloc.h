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

#ifndef GCM_TEST_ALLOC_H_
#define GCM_TEST_ALLOC_H_

#include "types.h"		// aligned_free() and posix_memalign() wrappers

#define DIM(x) (sizeof(x) / sizeof(x[0]))

static int vector_allocate(void **memory[], const size_t length[], const size_t align[],
			   const size_t num)
{
	int ret = 0;

	for (size_t n = 0; n < num; n++) {
		if (length[n] != 0) {
			const int use_memalign = ((align != NULL) && (align[n] != 0));
			void *ptr = NULL;
			int posix_ret = 0;

			if (use_memalign)
				posix_ret = posix_memalign(&ptr, align[n], length[n]);
			else
				ptr = malloc(length[n]);

			if (ptr == NULL || posix_ret != 0)
				ret = 1;	/* operation error */

			*memory[n] = ptr;
		} else {
			/* NULL pointer for zero length input */
			*memory[n] = NULL;
		}
	}

	if (ret)
		fprintf(stderr, "ERROR: Can't allocate required memory\n");

	return ret;
}

static int vector_free(void **memory[], const size_t align[], const size_t num)
{
	int ret = 0;

	for (size_t n = 0; n < num; n++) {
		if (memory[n] != NULL) {
			const int used_memalign = ((align != NULL) && (align[n] != 0));

			if (used_memalign)
				aligned_free(*memory[n]);
			else
				free(*memory[n]);

			*memory[n] = NULL;
		}
	}

	return ret;
}

#endif /* GCM_TEST_ALLOC_H_ */
