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
 * Internal RISC-V ZVKNED+ZVKB CTR32 helper for isa-l_crypto GCM wrappers.
 */

#if HAVE_RISCV_ZVK

.text
	.option arch, +v, +zvkned, +zvkb

#include "aes_zvk_macros.S"

#define INP	a0
#define OUTP	a1
#define LEN	a2
#define IVP	a3
#define KEYP	a4

#define LEN32	a5
#define VL_E32	a6
#define VL_BLOCKS	a7

.macro FUNC_START name
	.global \name
	.type   \name, %function
\name:
.endm

.macro FUNC_END name
	.size \name, .-\name
.endm

.macro	gcm_ctr32_crypt keylen
	addi		t0, LEN, 15
	srli		t0, t0, 4
	slli		LEN32, t0, 2

	li		t0, 0x88
	vsetvli		t1, zero, e8, m1, ta, ma
	vmv.v.x		v0, t0

	vsetivli	zero, 4, e32, m1, ta, mu
	vle32.v		v31, (IVP)

	vrev8.v		v31, v31, v0.t

	aes_load_keys	KEYP, \keylen

	/* AES operates on groups of four e32 lanes, one full 16-byte block. */
	vsetvli		VL_E32, LEN32, e32, m4, ta, mu
	andi		VL_E32, VL_E32, -4
	bnez		VL_E32, 3f
	li		VL_E32, 4
3:
	vsetvli		zero, VL_E32, e32, m4, ta, mu
	vmv.v.i		v16, 0
	vaesz.vs	v16, v31

	viota.m		v20, v0, v0.t
	vadd.vv		v16, v16, v20, v0.t

	j 2f
1:
	vsetvli		VL_E32, LEN32, e32, m4, ta, mu
	andi		VL_E32, VL_E32, -4
	bnez		VL_E32, 3f
	li		VL_E32, 4
3:
	vsetvli		zero, VL_E32, e32, m4, ta, mu
	vadd.vx		v16, v16, VL_BLOCKS, v0.t
2:
	vmv.v.v		v24, v16
	vrev8.v		v24, v24, v0.t

	aes_encrypt	v24, \keylen

	slli		t0, VL_E32, 2
	bleu		t0, LEN, 3f
	mv		t0, LEN
3:
	vsetvli		t0, t0, e8, m4, ta, ma
	vle8.v		v20, (INP)
	vxor.vv		v20, v20, v24
	vse8.v		v20, (OUTP)

	add		INP, INP, t0
	add		OUTP, OUTP, t0
	sub		LEN, LEN, t0
	sub		LEN32, LEN32, VL_E32
	srli		VL_BLOCKS, VL_E32, 2
	bnez		LEN, 1b

	vsetivli	zero, 4, e32, m1, ta, mu
	vadd.vx		v16, v16, VL_BLOCKS, v0.t
	vrev8.v		v16, v16, v0.t
	vse32.v		v16, (IVP)

	ret
.endm

FUNC_START aes_gcm_ctr32_crypt_128_zvkned_zvkb
	gcm_ctr32_crypt 128
FUNC_END aes_gcm_ctr32_crypt_128_zvkned_zvkb

FUNC_START aes_gcm_ctr32_crypt_256_zvkned_zvkb
	gcm_ctr32_crypt 256
FUNC_END aes_gcm_ctr32_crypt_256_zvkned_zvkb

#endif
