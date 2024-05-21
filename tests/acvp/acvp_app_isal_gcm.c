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
#include <stdlib.h>
#include <string.h>
#include <acvp/acvp.h>
#include <isa-l_crypto.h>

extern uint8_t verbose;

static int
aes_gcm_handler(ACVP_TEST_CASE *test_case)
{
        ACVP_RESULT ret = ACVP_SUCCESS;
        ACVP_SYM_CIPHER_TC *tc;

        static struct isal_gcm_key_data key;
        static struct isal_gcm_context_data gctx;
        uint8_t res_tag[16] = { 0 };

        if (verbose > 2)
                printf("aes gcm case\n");

        if (test_case == NULL)
                return EXIT_FAILURE;

        tc = test_case->tc.symmetric;

        if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
            tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
                fprintf(stderr, "Unsupported direction\n");
                return EXIT_FAILURE;
        }

        if (tc->iv_len != 12) {
                fprintf(stderr, "Unsupported IV\n");
                return EXIT_FAILURE;
        }

        switch (tc->key_len) {
        case 128:
                if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
                        if (tc->mct_index == 0) {
                                isal_aes_gcm_pre_128(tc->key, &key);
                                isal_aes_gcm_init_128(&key, &gctx, tc->iv, tc->aad, tc->aad_len);
                        }

                        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                isal_aes_gcm_enc_128_update(&key, &gctx, tc->ct, tc->pt,
                                                            tc->pt_len);
                        else
                                isal_aes_gcm_dec_128_update(&key, &gctx, tc->pt, tc->ct,
                                                            tc->ct_len);

                        if (tc->mct_index == ACVP_AES_MCT_INNER - 1) {
                                if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                        isal_aes_gcm_enc_128_finalize(&key, &gctx, tc->tag,
                                                                      tc->tag_len);
                                else
                                        isal_aes_gcm_dec_128_finalize(&key, &gctx, res_tag,
                                                                      tc->tag_len);
                        }
                } else {
                        memset(&gctx, 0, sizeof(gctx));
                        isal_aes_gcm_pre_128(tc->key, &key);

                        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                isal_aes_gcm_enc_128(&key, &gctx, tc->ct, tc->pt, tc->pt_len,
                                                     tc->iv, tc->aad, tc->aad_len, tc->tag,
                                                     tc->tag_len);
                        else
                                isal_aes_gcm_dec_128(&key, &gctx, tc->pt, tc->ct, tc->pt_len,
                                                     tc->iv, tc->aad, tc->aad_len, res_tag,
                                                     tc->tag_len);
                }
                break;
        case 256:
                if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT) {
                        if (tc->mct_index == 0) {
                                isal_aes_gcm_pre_256(tc->key, &key);
                                isal_aes_gcm_init_256(&key, &gctx, tc->iv, tc->aad, tc->aad_len);
                        }

                        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                isal_aes_gcm_enc_256_update(&key, &gctx, tc->ct, tc->pt,
                                                            tc->pt_len);
                        else
                                isal_aes_gcm_dec_256_update(&key, &gctx, tc->pt, tc->ct,
                                                            tc->ct_len);

                        if (tc->mct_index == ACVP_AES_MCT_INNER - 1) {
                                if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                        isal_aes_gcm_enc_256_finalize(&key, &gctx, tc->tag,
                                                                      tc->tag_len);
                                else
                                        isal_aes_gcm_dec_256_finalize(&key, &gctx, res_tag,
                                                                      tc->tag_len);
                        }
                } else {
                        memset(&gctx, 0, sizeof(gctx));
                        isal_aes_gcm_pre_256(tc->key, &key);

                        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                                isal_aes_gcm_enc_256(&key, &gctx, tc->ct, tc->pt, tc->pt_len,
                                                     tc->iv, tc->aad, tc->aad_len, tc->tag,
                                                     tc->tag_len);
                        else
                                isal_aes_gcm_dec_256(&key, &gctx, tc->pt, tc->ct, tc->pt_len,
                                                     tc->iv, tc->aad, tc->aad_len, res_tag,
                                                     tc->tag_len);
                }
                break;
        default:
                fprintf(stderr, "Unsupported AES-GCM key length %d\n", tc->key_len);
                ret = 1;
                goto end;
        }

        if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
                tc->ct_len = tc->pt_len;
        else {
                tc->pt_len = tc->ct_len;
                if (memcmp(res_tag, tc->tag, tc->tag_len) != 0)
                        return ACVP_CRYPTO_MODULE_FAIL;
        }

end:
        return ret;
}

int
enable_gcm(ACVP_CTX *ctx)
{
        ACVP_RESULT ret = ACVP_SUCCESS;

        if (verbose)
                printf(" Enable isa-l_crypto gcm\n");

        ret = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &aes_gcm_handler);
        if (ret != ACVP_SUCCESS)
                goto exit;

        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR,
                                            ACVP_SYM_CIPH_DIR_BOTH);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO,
                                            ACVP_SYM_CIPH_KO_NA);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC,
                                            ACVP_SYM_CIPH_IVGEN_SRC_INT);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE,
                                            ACVP_SYM_CIPH_IVGEN_MODE_821);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 256);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 128);
        ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
        ret |= acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_PTLEN, 0,
                                              65536, 256);
        ret |= acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_DOMAIN_AADLEN, 0,
                                              65536, 256);
exit:
        return ret;
}
