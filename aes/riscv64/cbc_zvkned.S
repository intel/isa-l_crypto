/**********************************************************************
  Copyright (c) 2026 Institute of Software Chinese Academy of Sciences (ISCAS).

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of ISCAS nor the names of its
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

/*
 * RISC-V ZVKNED AES-CBC providers for isa-l_crypto.
 */

#if HAVE_RISCV_ZVK

.text
	.option arch, +v, +zvkned, +zvkb

#include "aes_zvk_macros.S"

#define INP	a0
#define IVP	a1
#define KEYP	a2
#define OUTP	a3
#define LEN		a4

.macro FUNC_START name
	.global \name
	.type   \name, %function
\name:
.endm

.macro FUNC_END name
	.size \name, .-\name
.endm

.macro	aes_cbc_encrypt keylen
	vle32.v		v16, (IVP)
1:
	vle32.v		v17, (INP)
	vxor.vv		v16, v16, v17
	aes_encrypt	v16, \keylen
	vse32.v		v16, (OUTP)
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		LEN, LEN, -16
	bnez		LEN, 1b

	ret
.endm

.macro	aes_cbc_decrypt keylen
	srli		LEN, LEN, 2
	vle32.v		v16, (IVP)
1:
	/* Keep each vector operation on a complete 16-byte AES block boundary. */
	vsetvli		t0, LEN, e32, m4, ta, ma
	andi		t0, t0, -4
	bnez		t0, 2f
	li		t0, 4
2:
	vsetvli		zero, t0, e32, m4, ta, ma
	vle32.v		v20, (INP)
	vslideup.vi	v16, v20, 4
	addi		t1, t0, -4
	vslidedown.vx	v24, v20, t1
	aes_decrypt_enc_keys	v20, \keylen
	vxor.vv		v20, v20, v16
	vse32.v		v20, (OUTP)
	vmv.v.v		v16, v24
	slli		t1, t0, 2
	add		INP, INP, t1
	add		OUTP, OUTP, t1
	sub		LEN, LEN, t0
	bnez		LEN, 1b

	ret
.endm

FUNC_START aes_cbc_enc_128_zvkned_impl
	aes_load_keys	KEYP, 128
	aes_cbc_encrypt	128
FUNC_END aes_cbc_enc_128_zvkned_impl

FUNC_START aes_cbc_enc_192_zvkned_impl
	aes_load_keys	KEYP, 192
	aes_cbc_encrypt	192
FUNC_END aes_cbc_enc_192_zvkned_impl

FUNC_START aes_cbc_enc_256_zvkned_impl
	aes_load_keys	KEYP, 256
	aes_cbc_encrypt	256
FUNC_END aes_cbc_enc_256_zvkned_impl

FUNC_START aes_cbc_dec_128_zvkned_impl
	aes_load_dec_keys_as_enc	KEYP, 128
	aes_cbc_decrypt	128
FUNC_END aes_cbc_dec_128_zvkned_impl

FUNC_START aes_cbc_dec_192_zvkned_impl
	aes_load_dec_keys_as_enc	KEYP, 192
	aes_cbc_decrypt	192
FUNC_END aes_cbc_dec_192_zvkned_impl

FUNC_START aes_cbc_dec_256_zvkned_impl
	aes_load_dec_keys_as_enc	KEYP, 256
	aes_cbc_decrypt	256
FUNC_END aes_cbc_dec_256_zvkned_impl

#endif
