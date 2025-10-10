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

#include <aes_keyexp.h>
#include <aes_xts.h>

#include "aes_256_xts_test.json.h"
int
main(void)
{

        // Temporary array for the calculated vectors
        uint8_t *ct_test = NULL;
        uint8_t *pt_test = NULL;
        // Arrays for expanded keys, null_key is a dummy vector (decrypt key not
        // needed for the tweak part of the decryption)
        uint8_t expkey1_enc[16 * 15], expkey2_enc[16 * 15];
        uint8_t expkey1_dec[16 * 15], null_key[16 * 15];

        size_t j;
        int retval, ret = -1;

        const struct cipher_test *v = xts_256_test_json;

        // --- Encryption test ---

        // Loop over the vectors
        for (; v->msg != NULL; v++) {
                const size_t buf_size = v->msgSize / 8;

                // Allocate space for the calculated ciphertext
                ct_test = malloc(buf_size);
                if (ct_test == NULL) {
                        printf("Can't allocate ciphertext memory\n");
                        goto end;
                }
                // Pre-expand keys (will only use the encryption ones here)
                isal_aes_keyexp_256((const uint8_t *) v->key, expkey1_enc, expkey1_dec);
                isal_aes_keyexp_256((const uint8_t *) v->key + 32, expkey2_enc, null_key);

                isal_aes_xts_enc_256_expanded_key(expkey2_enc, expkey1_enc, (const uint8_t *) v->iv,
                                                  buf_size, v->msg, ct_test);

                // Carry out comparison of the calculated ciphertext with
                // the reference
                retval = memcmp(ct_test, v->ct, buf_size);

                if (retval != 0) {
                        for (j = 0; j < buf_size; j++) {
                                if (ct_test[j] != (const uint8_t) v->ct[j]) {
                                        printf("\nXTS_AES_256_expanded_key_enc: Vector %zu: (size "
                                               "= %zu bytes) ",
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
        for (v = xts_256_test_json; v->msg != NULL; v++) {
                const size_t buf_size = v->msgSize / 8;

                // Allocate space for the calculated ciphertext
                pt_test = malloc(buf_size);
                if (pt_test == NULL) {
                        printf("Can't allocate plaintext memory\n");
                        goto end;
                }
                // Pre-expand keys for the decryption
                isal_aes_keyexp_256((const uint8_t *) v->key, expkey1_enc, expkey1_dec);
                isal_aes_keyexp_256((const uint8_t *) v->key + 32, expkey2_enc, null_key);

                // Note, encryption key is reused for the tweak decryption step
                isal_aes_xts_dec_256_expanded_key(expkey2_enc, expkey1_dec, (const uint8_t *) v->iv,
                                                  buf_size, v->ct, pt_test);

                retval = memcmp(pt_test, v->msg, buf_size);

                if (retval != 0) {
                        for (j = 0; j < buf_size; j++) {
                                if (pt_test[j] != (const uint8_t) v->msg[j]) {
                                        printf("\nXTS_AES_256_expanded_key_dec: Vector %zu: (size "
                                               "= %zu bytes) ",
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
