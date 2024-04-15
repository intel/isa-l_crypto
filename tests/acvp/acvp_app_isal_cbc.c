/**********************************************************************
  Copyright(c) 2022, Intel Corporation All rights reserved.

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

#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <acvp/acvp.h>
#include <isa-l_crypto.h>

extern uint8_t verbose;

static int
aes_cbc_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_RESULT ret = ACVP_SUCCESS;
        ACVP_SYM_CIPHER_TC *tc;
        struct cbc_key_data keys;
        static uint8_t next_iv[16];
        void *iv = NULL;

        if (verbose > 2)
                printf("aes cbc case\n");

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                ret = EXIT_FAILURE;
                goto err;
        }

        /*
         * If Monte-carlo test, use the IV from the ciphertext of
         * the previous iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT && tc->mct_index != 0)
                iv = next_iv;
        else
                iv = tc->iv;

        switch (tc->key_len) {
        case 128:
                aes_keyexp_128(tc->key, keys.enc_keys, keys.dec_keys);

                if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                        aes_cbc_enc_128(tc->pt, iv, keys.enc_keys, tc->ct, tc->pt_len);
                else
                        aes_cbc_dec_128(tc->ct, iv, keys.dec_keys, tc->pt, tc->ct_len);
                break;
        case 192:
                aes_keyexp_192(tc->key, keys.enc_keys, keys.dec_keys);

                if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                        aes_cbc_enc_192(tc->pt, iv, keys.enc_keys, tc->ct, tc->pt_len);
                else
                        aes_cbc_dec_192(tc->ct, iv, keys.dec_keys, tc->pt, tc->ct_len);
                break;
        case 256:
                aes_keyexp_256(tc->key, keys.enc_keys, keys.dec_keys);

                if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                        aes_cbc_enc_256(tc->pt, iv, keys.enc_keys, tc->ct, tc->pt_len);
                else
                        aes_cbc_dec_256(tc->ct, iv, keys.dec_keys, tc->pt, tc->ct_len);
                break;
        default:
                fprintf(stderr, "Unsupported AES key length\n");
                ret = 1;
                goto err;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                tc->ct_len = tc->pt_len;
        else
                tc->pt_len = tc->ct_len;

        /*
         * If Monte-carlo test, copy the ciphertext for
         * the IV of the next iteration
         */
        if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
                memcpy(next_iv, tc->ct, 16);

err:
        return ret;
}

int
enable_cbc(ACVP_CTX *ctx)
{
        ACVP_RESULT ret = ACVP_SUCCESS;

        if (verbose)
                printf(" Enable isa-l_crypto cbc\n");

        ret = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_CBC, &aes_cbc_handler);
        if (ret != ACVP_SUCCESS)
                goto exit;

        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_DIR,
                                            ACVP_SYM_CIPH_DIR_BOTH);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_KO,
                                            ACVP_SYM_CIPH_KO_NA);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_SRC,
                                            ACVP_SYM_CIPH_IVGEN_SRC_NA);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_PARM_IVGEN_MODE,
                                            ACVP_SYM_CIPH_IVGEN_MODE_NA);

        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 128);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 192);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_CBC, ACVP_SYM_CIPH_KEYLEN, 256);

exit:
        return ret;
}
