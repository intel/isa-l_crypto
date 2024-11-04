/**********************************************************************
  Copyright(c) 2011-2024 Intel Corporation All rights reserved.

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <aes_xts.h>
#include "aes_128_xts_test.json.h"

int
main(void)
{

        // Temporary array for the calculated vectors
        uint8_t *ct_test = NULL;
        uint8_t *pt_test = NULL;

        size_t j;
        int retval, ret = -1;

        const struct cipher_test *v = xts_128_test_json;
        // --- Encryption test ---

        // Loop over the vectors
        for (; v->msg != NULL; v++) {
                const size_t buf_size = v->msgSize / 8;

                // Allocate space for the calculated ciphertext
                ct_test = malloc(buf_size);
                if (ct_test == NULL) {
                        fprintf(stderr, "Can't allocate ciphertext memory\n");
                        goto end;
                }

                isal_aes_xts_enc_128((const uint8_t *) v->key + 16, (const uint8_t *) v->key,
                                     (const uint8_t *) v->iv, buf_size, v->msg, ct_test);

                // Carry out comparison of the calculated ciphertext with
                // the reference
                retval = memcmp(ct_test, v->ct, buf_size);

                if (retval != 0) {
                        for (j = 0; j < buf_size; j++) {
                                if (ct_test[j] != (const uint8_t) v->ct[j]) {
                                        printf("\nXTS_AES_128_enc: Vector %zu: (size = %zu bytes) ",
                                               v->tcId, buf_size);
                                        printf("failed at byte %zu! \n", j);
                                        goto end;
                                }
                        }
                }
                printf(".");

                free(ct_test);
                ct_test = NULL;
        }

        // --- Decryption test ---

        // Loop over the vectors
        for (v = xts_128_test_json; v->msg != NULL; v++) {
                const size_t buf_size = v->msgSize / 8;

                // Allocate space for the calculated ciphertext
                pt_test = malloc(buf_size);
                if (pt_test == NULL) {
                        fprintf(stderr, "Can't allocate plaintext memory\n");
                        goto end;
                }

                isal_aes_xts_dec_128((const uint8_t *) v->key + 16, (const uint8_t *) v->key,
                                     (const uint8_t *) v->iv, buf_size, v->ct, pt_test);

                retval = memcmp(pt_test, v->msg, buf_size);

                if (retval != 0) {
                        for (j = 0; j < buf_size; j++) {
                                if (pt_test[j] != (const uint8_t) v->msg[j]) {
                                        printf("\nXTS_AES_128_dec: Vector %zu: (size = %zu bytes) ",
                                               v->tcId, buf_size);
                                        printf("failed at byte %zu! \n", j);
                                        goto end;
                                }
                        }
                }
                printf(".");

                free(pt_test);
                pt_test = NULL;
        }
        ret = 0;
        printf("Pass\n");

end:
        if (ct_test != NULL)
                free(ct_test);
        if (pt_test != NULL)
                free(pt_test);

        return ret;
}
