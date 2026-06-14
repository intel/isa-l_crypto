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
 * Internal RISC-V ZVKNED AES block helpers for isa-l_crypto wrappers.
 */

#if HAVE_RISCV_ZVK

.text
	.option arch, +v, +zvkned, +zvkb

#include "aes_zvk_macros.S"

#define INP	a0
#define OUTP	a1
#define KEYP	a2
#define BLOCKS	a2
#define TWEAKP	a3
#define XTS_KEYP	a4

.macro FUNC_START name
	.global \name
	.type   \name, %function
\name:
.endm

.macro FUNC_END name
	.size \name, .-\name
.endm

.macro aes_block_encrypt keylen
	aes_load_keys	KEYP, \keylen
	vle32.v		v16, (INP)
	aes_encrypt	v16, \keylen
	vse32.v		v16, (OUTP)
	ret
.endm

.macro aes_block_decrypt keylen
	aes_load_keys	KEYP, \keylen
	vle32.v		v16, (INP)
	aes_decrypt_enc_keys	v16, \keylen
	vse32.v		v16, (OUTP)
	ret
.endm

.macro aes_block_decrypt_dec_keys keylen
	aes_load_dec_keys_as_enc	KEYP, \keylen
	vle32.v		v16, (INP)
	aes_decrypt_enc_keys	v16, \keylen
	vse32.v		v16, (OUTP)
	ret
.endm

.macro xts_mul_alpha tweak
	vsetivli	zero, 16, e8, m1, ta, ma
	vsrl.vi		v18, \tweak, 7
	vsll.vi		\tweak, \tweak, 1
	vmv.v.i		v19, 0
	vslideup.vi	v19, v18, 1
	vor.vv		\tweak, \tweak, v19
	vslidedown.vi	v20, v18, 15
	vmv.x.s		t0, v20
	andi		t0, t0, 1
	beqz		t0, .Lxts_mul_done\@
	li		t0, 0x87
	vmv.v.i		v19, 0
	vsetivli	zero, 1, e8, m1, tu, ma
	vmv.s.x		v19, t0
	vsetivli	zero, 16, e8, m1, ta, ma
	vxor.vv		\tweak, \tweak, v19
.Lxts_mul_done\@:
	vsetivli	zero, 4, e32, m1, ta, ma
.endm

.macro aes_xts_encrypt_blocks_128
	beqz		BLOCKS, 2f
	aes_load_keys	XTS_KEYP, 128
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_encrypt	v16, 128
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

.macro aes_xts_decrypt_blocks_128
	beqz		BLOCKS, 2f
	aes_load_keys	XTS_KEYP, 128
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_decrypt_enc_keys	v16, 128
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

.macro aes_xts_decrypt_blocks_128_dec_keys
	beqz		BLOCKS, 2f
	aes_load_dec_keys_as_enc	XTS_KEYP, 128
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_decrypt_enc_keys	v16, 128
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

.macro aes_xts_encrypt_blocks_256
	beqz		BLOCKS, 2f
	aes_load_keys	XTS_KEYP, 256
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_encrypt	v16, 256
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

.macro aes_xts_decrypt_blocks_256
	beqz		BLOCKS, 2f
	aes_load_keys	XTS_KEYP, 256
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_decrypt_enc_keys	v16, 256
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

.macro aes_xts_decrypt_blocks_256_dec_keys
	beqz		BLOCKS, 2f
	aes_load_dec_keys_as_enc	XTS_KEYP, 256
	vle32.v		v17, (TWEAKP)
1:
	vle32.v		v16, (INP)
	vxor.vv		v16, v16, v17
	aes_decrypt_enc_keys	v16, 256
	vxor.vv		v16, v16, v17
	vse32.v		v16, (OUTP)
	xts_mul_alpha	v17
	addi		INP, INP, 16
	addi		OUTP, OUTP, 16
	addi		BLOCKS, BLOCKS, -1
	bnez		BLOCKS, 1b
	vse32.v		v17, (TWEAKP)
2:
	ret
.endm

FUNC_START aes_encrypt_block_128_zvkned
	aes_block_encrypt 128
FUNC_END aes_encrypt_block_128_zvkned

FUNC_START aes_encrypt_block_256_zvkned
	aes_block_encrypt 256
FUNC_END aes_encrypt_block_256_zvkned

FUNC_START aes_decrypt_block_128_zvkned
	aes_block_decrypt 128
FUNC_END aes_decrypt_block_128_zvkned

FUNC_START aes_decrypt_block_256_zvkned
	aes_block_decrypt 256
FUNC_END aes_decrypt_block_256_zvkned

FUNC_START aes_decrypt_block_128_dec_keys_zvkned
	aes_block_decrypt_dec_keys 128
FUNC_END aes_decrypt_block_128_dec_keys_zvkned

FUNC_START aes_decrypt_block_256_dec_keys_zvkned
	aes_block_decrypt_dec_keys 256
FUNC_END aes_decrypt_block_256_dec_keys_zvkned

FUNC_START aes_xts_enc_blocks_128_zvkned
	aes_xts_encrypt_blocks_128
FUNC_END aes_xts_enc_blocks_128_zvkned

FUNC_START aes_xts_dec_blocks_128_zvkned
	aes_xts_decrypt_blocks_128
FUNC_END aes_xts_dec_blocks_128_zvkned

FUNC_START aes_xts_dec_blocks_128_dec_keys_zvkned
	aes_xts_decrypt_blocks_128_dec_keys
FUNC_END aes_xts_dec_blocks_128_dec_keys_zvkned

FUNC_START aes_xts_enc_blocks_256_zvkned
	aes_xts_encrypt_blocks_256
FUNC_END aes_xts_enc_blocks_256_zvkned

FUNC_START aes_xts_dec_blocks_256_zvkned
	aes_xts_decrypt_blocks_256
FUNC_END aes_xts_dec_blocks_256_zvkned

FUNC_START aes_xts_dec_blocks_256_dec_keys_zvkned
	aes_xts_decrypt_blocks_256_dec_keys
FUNC_END aes_xts_dec_blocks_256_dec_keys_zvkned

#endif
