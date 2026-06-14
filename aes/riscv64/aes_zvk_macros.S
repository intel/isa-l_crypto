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
 * Shared AES macros for RISC-V Zvk providers.
 */

/*
 * Loads AES round keys from \keyp into vector registers.
 *
 * The expanded key layout in isa-l_crypto is a flat array of 16-byte round
 * keys. The key length and whether the loaded keys are encryption or
 * decryption schedules are known from the selected provider symbol.
 */
.macro	aes_load_keys keyp, keylen
	vsetivli	zero, 4, e32, m1, ta, ma
	vle32.v		v1, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v2, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v3, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v4, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v5, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v6, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v7, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v8, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v9, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v10, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v11, (\keyp)
.if \keylen >= 192
	addi		\keyp, \keyp, 16
	vle32.v		v12, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v13, (\keyp)
.endif
.if \keylen == 256
	addi		\keyp, \keyp, 16
	vle32.v		v14, (\keyp)
	addi		\keyp, \keyp, 16
	vle32.v		v15, (\keyp)
.endif
.endm

.macro	aes_mix_columns_key key
	vror.vi		v28, \key, 8
	vror.vi		v29, \key, 16
	vror.vi		v30, \key, 24

	vxor.vv		v31, \key, v28
	li		t2, 0x80808080
	vand.vx		v27, v31, t2
	vsrl.vi		v27, v27, 7
	li		t2, 0x1b
	vmul.vx		v27, v27, t2
	li		t2, 0x7f7f7f7f
	vand.vx		v31, v31, t2
	vsll.vi		v31, v31, 1
	vxor.vv		v31, v31, v27

	vxor.vv		\key, v28, v29
	vxor.vv		\key, \key, v30
	vxor.vv		\key, \key, v31
.endm

.macro	aes_load_dec_middle_key keyp, reg
	addi		\keyp, \keyp, -16
	vle32.v		\reg, (\keyp)
	aes_mix_columns_key	\reg
.endm

.macro	aes_load_dec_keys_as_enc keyp, keylen
	vsetivli	zero, 4, e32, m1, ta, ma
.if \keylen == 128
	vle32.v		v11, (\keyp)
	addi		\keyp, \keyp, 160
	vle32.v		v1, (\keyp)
	.irp reg, v2, v3, v4, v5, v6, v7, v8, v9, v10
	aes_load_dec_middle_key	\keyp, \reg
	.endr
.elseif \keylen == 192
	vle32.v		v13, (\keyp)
	addi		\keyp, \keyp, 192
	vle32.v		v1, (\keyp)
	.irp reg, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12
	aes_load_dec_middle_key	\keyp, \reg
	.endr
.else
	vle32.v		v15, (\keyp)
	addi		\keyp, \keyp, 224
	vle32.v		v1, (\keyp)
	.irp reg, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14
	aes_load_dec_middle_key	\keyp, \reg
	.endr
.endif
.endm

.macro	aes_encrypt data, keylen
	vaesz.vs	\data, v1
	vaesem.vs	\data, v2
	vaesem.vs	\data, v3
	vaesem.vs	\data, v4
	vaesem.vs	\data, v5
	vaesem.vs	\data, v6
	vaesem.vs	\data, v7
	vaesem.vs	\data, v8
	vaesem.vs	\data, v9
	vaesem.vs	\data, v10
.if \keylen == 128
	vaesef.vs	\data, v11
.elseif \keylen == 192
	vaesem.vs	\data, v11
	vaesem.vs	\data, v12
	vaesef.vs	\data, v13
.else
	vaesem.vs	\data, v11
	vaesem.vs	\data, v12
	vaesem.vs	\data, v13
	vaesem.vs	\data, v14
	vaesef.vs	\data, v15
.endif
.endm

.macro	aes_decrypt_enc_keys data, keylen
.if \keylen == 128
	vaesz.vs	\data, v11
.elseif \keylen == 192
	vaesz.vs	\data, v13
	vaesdm.vs	\data, v12
	vaesdm.vs	\data, v11
.else
	vaesz.vs	\data, v15
	vaesdm.vs	\data, v14
	vaesdm.vs	\data, v13
	vaesdm.vs	\data, v12
	vaesdm.vs	\data, v11
.endif
	vaesdm.vs	\data, v10
	vaesdm.vs	\data, v9
	vaesdm.vs	\data, v8
	vaesdm.vs	\data, v7
	vaesdm.vs	\data, v6
	vaesdm.vs	\data, v5
	vaesdm.vs	\data, v4
	vaesdm.vs	\data, v3
	vaesdm.vs	\data, v2
	vaesdf.vs	\data, v1
.endm
