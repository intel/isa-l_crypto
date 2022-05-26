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
#include <acvp/acvp.h>
#include <isa-l_crypto.h>

extern uint8_t verbose;

static int aes_xts_handler(ACVP_TEST_CASE * test_case)
{
	ACVP_RESULT ret = ACVP_SUCCESS;
	ACVP_SYM_CIPHER_TC *tc;
	uint8_t *tinit = 0;
	uint8_t *key;

	if (verbose > 2)
		printf("aes xts case\n");

	if (test_case == NULL)
		return EXIT_FAILURE;

	tc = test_case->tc.symmetric;
	key = tc->key;

	if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT &&
	    tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
		fprintf(stderr, "Unsupported direction\n");
		return EXIT_FAILURE;
	}

	switch (tc->tw_mode) {
	case ACVP_SYM_CIPH_TWEAK_HEX:
		tinit = tc->iv;
		break;
	case ACVP_SYM_CIPH_TWEAK_NUM:
	case ACVP_SYM_CIPH_TWEAK_NONE:
	default:
		fprintf(stderr, "\nUnsupported tweak mode NUM/NONE\n");
		ret = 1;
		goto err;
		break;
	}

	switch (tc->key_len) {
	case 128:
		if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
			XTS_AES_128_enc(&key[16], &key[0], tinit, tc->pt_len, tc->pt, tc->ct);
		else
			XTS_AES_128_dec(&key[16], &key[0], tinit, tc->ct_len, tc->ct, tc->pt);
		break;
	case 256:
		if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT)
			XTS_AES_256_enc(&key[32], &key[0], tinit, tc->pt_len, tc->pt, tc->ct);
		else
			XTS_AES_256_dec(&key[32], &key[0], tinit, tc->ct_len, tc->ct, tc->pt);
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

      err:
	return ret;
}

int enable_xts(ACVP_CTX * ctx)
{
	ACVP_RESULT ret = ACVP_SUCCESS;

	if (verbose)
		printf(" Enable isa-l_crypto xts\n");

	ret = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_XTS, &aes_xts_handler);
	if (ret != ACVP_SUCCESS)
		goto exit;

	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_PARM_IVGEN_SRC,
					    ACVP_SYM_CIPH_IVGEN_SRC_NA);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_PARM_IVGEN_MODE,
					    ACVP_SYM_CIPH_IVGEN_MODE_NA);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 128);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS, ACVP_SYM_CIPH_KEYLEN, 256);
	ret |= acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS,
					      ACVP_SYM_CIPH_DOMAIN_PTLEN, 256, 65536, 256);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_TWEAK, ACVP_SYM_CIPH_TWEAK_HEX);
	ret |= acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_XTS,
					    ACVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN, 0);
	ret |= acvp_cap_sym_cipher_set_domain(ctx, ACVP_AES_XTS,
					      ACVP_SYM_CIPH_DOMAIN_DULEN, 256, 65536, 256);

      exit:
	return ret;
}
