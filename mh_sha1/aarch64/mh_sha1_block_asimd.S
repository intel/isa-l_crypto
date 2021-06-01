/**********************************************************************
  Copyright(c) 2021 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
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

	.arch armv8-a

.macro  declare_var_vector_reg name:req,reg:req
	\name	.req      v\reg
.endm

/* macro F = (D ^ (B & (C ^ D))) */
.macro FUNC_F0 reg_f:req,reg_b:req,reg_c:req,reg_d:req
	eor	\reg_f\().16b, \reg_c\().16b, \reg_d\().16b
	and	\reg_f\().16b, \reg_b\().16b, \reg_f\().16b
	eor	\reg_f\().16b, \reg_d\().16b, \reg_f\().16b
.endm

/* F = (B ^ C ^ D) */
.macro FUNC_F1 reg_f:req,reg_b:req,reg_c:req,reg_d:req
	eor	\reg_f\().16b, \reg_b\().16b, \reg_c\().16b
	eor	\reg_f\().16b, \reg_f\().16b, \reg_d\().16b
.endm

/* F = ((B & C) | (B & D) | (C & D)) */
.macro FUNC_F2 reg_f:req,reg_b:req,reg_c:req,reg_d:req
	and	vT0.16b, \reg_b\().16b, \reg_c\().16b
	and	vT1.16b, \reg_b\().16b, \reg_d\().16b
	and	vT2.16b, \reg_c\().16b, \reg_d\().16b
	orr	\reg_f\().16b, vT0.16b, vT1.16b
	orr	\reg_f\().16b, \reg_f\().16b, vT2.16b
.endm

/* F = (B ^ C ^ D) */
.macro FUNC_F3 reg_f:req,reg_b:req,reg_c:req,reg_d:req
	FUNC_F1	\reg_f,\reg_b,\reg_c,\reg_d
.endm

.macro SHA1_STEP_00_15 reg_a:req,reg_b:req,reg_c:req,reg_d:req,reg_e:req,reg_f:req,windex:req,reg_k:req,data:req,func_f:req,reg_t:req
	// e = (a leftrotate 5) + f + e + k + w[i]
	ushr	\reg_t\().4s, \reg_a\().4s, 32 - 5
	add	\reg_e\().4s, \reg_e\().4s, \reg_k\().4s
	add	tmp, \data, (\windex * 16)
	ld1	{\reg_f\().4s}, [tmp]
	sli	\reg_t\().4s, \reg_a\().4s, 5
	add	\reg_e\().4s, \reg_e\().4s, \reg_f\().4s
	add	\reg_e\().4s, \reg_e\().4s, \reg_t\().4s
	ushr	\reg_t\().4s, \reg_b\().4s, 32 - 30
	\func_f	\reg_f\(), \reg_b\(), \reg_c\(), \reg_d\()
	add	\reg_e\().4s, \reg_e\().4s, \reg_f\().4s
	sli	\reg_t\().4s, \reg_b\().4s, 30
	mov	\reg_b\().16b, \reg_t\().16b
.endm

.macro SHA1_STEP_16_79 reg_a:req,reg_b:req,reg_c:req,reg_d:req,reg_e:req,reg_f:req,windex:req,reg_k:req,data:req,func_f:req,reg_t:req
	/* w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1 */
	add	tmp, \data, #(((\windex - 14) & 15) * 16)
	ld1	{vT1.4s}, [tmp]
	add	tmp, \data, #(((\windex - 8) & 15) * 16)
	ld1	{vT2.4s}, [tmp]
	add	tmp, \data, #(((\windex - 3) & 15) * 16)
	ld1	{vT3.4s}, [tmp]
	add	tmp, \data, #((\windex & 15) * 16)
	ld1	{vT0.4s}, [tmp]
	eor	vT1.16b, vT1.16b, vT2.16b
	eor	vT0.16b, vT0.16b, vT3.16b
	eor	vT0.16b, vT0.16b, vT1.16b
	// e = (a leftrotate 5) + f + e + k + w[i]
	ushr	\reg_t\().4s, vT0.4s, 32 - 1
	add	\reg_e\().4s, \reg_e\().4s, \reg_k\().4s
	ushr	vT1.4s, \reg_a\().4s, 32 - 5
	sli	\reg_t\().4s, vT0.4s, 1
	add	\reg_e\().4s, \reg_e\().4s, \reg_t\().4s
	sli	vT1.4s, \reg_a\().4s, 5
	st1	{\reg_t\().4s}, [tmp]
	add	\reg_e\().4s, \reg_e\().4s, vT1.4s
	mov	\reg_t\().16b, \reg_b\().16b
	\func_f	\reg_f\(), \reg_b\(), \reg_c\(), \reg_d\()
	ushr	\reg_b\().4s, \reg_t\().4s, 32 - 30
	add	\reg_e\().4s, \reg_e\().4s, \reg_f\().4s
	sli	\reg_b\().4s, \reg_t\().4s, 30
.endm

declare_var_vector_reg	VA, 0
declare_var_vector_reg	VB, 1
declare_var_vector_reg	VC, 2
declare_var_vector_reg	VD, 3
declare_var_vector_reg	VE, 4
declare_var_vector_reg	VF, 5
declare_var_vector_reg	vKey, 6
declare_var_vector_reg	vTmp, 7
declare_var_vector_reg	vT0, 16
declare_var_vector_reg	vT1, 17
declare_var_vector_reg	vT2, 18
declare_var_vector_reg	vT3, 19
declare_var_vector_reg	vAA, 20
declare_var_vector_reg	vBB, 21
declare_var_vector_reg	vCC, 22
declare_var_vector_reg	vDD, 23
declare_var_vector_reg	vEE, 24
declare_var_vector_reg	TT, 0

.macro SWAP_STATES
	.unreq TT
	TT .req VE
	.unreq VE
	VE .req VD
	.unreq VD
	VD .req VC
	.unreq VC
	VC .req VB
	.unreq VB
	VB .req VA
	.unreq VA
	VA .req TT
.endm

/*
 * void mh_sha1_block_asimd (const uint8_t * input_data,
 *                           uint32_t mh_sha1_digests[SHA1_DIGEST_WORDS][HASH_SEGS],
 *                           uint8_t frame_buffer[MH_SHA1_BLOCK_SIZE],
 *                           uint32_t num_blocks);
 * arg 0 pointer to input data
 * arg 1 pointer to digests, include segments digests(uint32_t digests[16][5])
 * arg 2 pointer to aligned_frame_buffer which is used to save the big_endian data.
 * arg 3 number  of 1KB blocks
 */

	input_data	.req	x0
	sha1_digest	.req	x1
	data_buf	.req	x2
	num_blocks	.req	w3

	src	.req	x5
	dst	.req	x6
	offs	.req	x7
	mh_segs	.req	x8
	key	.req	w9
	key_adr	.req	x9
	tmp	.req	x10

	.global mh_sha1_block_asimd
	.type mh_sha1_block_asimd, %function
mh_sha1_block_asimd:
	cmp	num_blocks, #0
	beq	.return

.block_loop:
	mov	src, input_data
.set counter, 0

.rept 16
	// reverse the input data to big-endian
	// and transform input data from DWORD*16_SEGS to DWORD*4_SEGS * 4
	// so that we are able to process 4 SEGS each time by 128-bit NEON
	ld1	{vT0.4S, vT1.4S, vT2.4S, vT3.4S}, [src], #64

	rev32	vT0.16b, vT0.16b
	add	dst, data_buf, counter * 16
	rev32	vT1.16b, vT1.16b
	st1	{vT0.4S}, [dst]
	add	dst, dst, 256
	rev32	vT2.16b, vT2.16b
	st1	{vT1.4S}, [dst]
	add	dst, dst, 256
	rev32	vT3.16b, vT3.16b
	st1	{vT2.4S}, [dst]
	add	dst, dst, 256
	st1	{vT3.4S}, [dst]

	.set counter, counter+1
.endr

	mov	mh_segs, #0

.seg_loops:
	mov	offs, #64
	/* load four segments of digest each time */
	add	src, sha1_digest, mh_segs
	ld1	{VA.4S}, [src], offs
	ld1	{VB.4S}, [src], offs
	mov	vAA.16B, VA.16B
	ld1	{VC.4S}, [src], offs
	mov	vBB.16B, VB.16B
	ld1	{VD.4S}, [src], offs
	mov	vCC.16B, VC.16B
	ld1	{VE.4S}, [src], offs
	mov	vDD.16B, VD.16B
	mov	vEE.16B, VE.16B

	.set WI, 0

	adr	key_adr, KEY_0
	ld1	{vKey.4s}, [key_adr]

	// 0 ~ 15
.rept 16
	SHA1_STEP_00_15	VA,VB,VC,VD,VE,VF,WI,vKey,data_buf,FUNC_F0,vTmp
	SWAP_STATES
	.set WI, WI + 1
.endr

	// 16 ~ 19
.rept 4
	SHA1_STEP_16_79	VA,VB,VC,VD,VE,VF,WI,vKey,data_buf,FUNC_F0,vTmp
	SWAP_STATES
	.set WI, WI + 1
.endr

	// 20 ~ 39
	adr	key_adr, KEY_1
	ld1	{vKey.4s}, [key_adr]
.rept 20
	SHA1_STEP_16_79	VA,VB,VC,VD,VE,VF,WI,vKey,data_buf,FUNC_F1,vTmp

	SWAP_STATES
	.set WI, WI + 1
.endr

	// 40 ~ 59
	adr	key_adr, KEY_2
	ld1	{vKey.4s}, [key_adr]
.rept 20
	SHA1_STEP_16_79	VA,VB,VC,VD,VE,VF,WI,vKey,data_buf,FUNC_F2,vTmp
	SWAP_STATES
	.set WI, WI + 1
.endr

	// 60 ~ 79
	adr	key_adr, KEY_3
	ld1	{vKey.4s}, [key_adr]
.rept 20
	SHA1_STEP_16_79	VA,VB,VC,VD,VE,VF,WI,vKey,data_buf,FUNC_F3,vTmp
	SWAP_STATES
	.set WI, WI + 1
.endr

	add	VA.4s, vAA.4s, VA.4s
	mov	offs, #64
	add	dst, sha1_digest, mh_segs
	add	VB.4s, vBB.4s, VB.4s
	st1	{VA.4S}, [dst], offs
	add	VC.4s, vCC.4s, VC.4s
	st1	{VB.4S}, [dst], offs
	add	VD.4s, vDD.4s, VD.4s
	st1	{VC.4S}, [dst], offs
	add	VE.4s, vEE.4s, VE.4s
	st1	{VD.4S}, [dst], offs
	st1	{VE.4S}, [dst], offs

	add	data_buf, data_buf, 256
	add	mh_segs, mh_segs, #16
	cmp	mh_segs, #64
	bne	.seg_loops

	sub	data_buf, data_buf, 1024
	add	input_data, input_data, 1024
	subs	num_blocks, num_blocks, 1
	bne	.block_loop

.return:
	ret

	.size mh_sha1_block_asimd, .-mh_sha1_block_asimd
	.section .rodata.cst16,"aM",@progbits,16
	.align  16
KEY_0:
	.word	0x5a827999
	.word	0x5a827999
	.word	0x5a827999
	.word	0x5a827999
KEY_1:
	.word	0x6ed9eba1
	.word	0x6ed9eba1
	.word	0x6ed9eba1
	.word	0x6ed9eba1
KEY_2:
	.word	0x8f1bbcdc
	.word	0x8f1bbcdc
	.word	0x8f1bbcdc
	.word	0x8f1bbcdc
KEY_3:
	.word	0xca62c1d6
	.word	0xca62c1d6
	.word	0xca62c1d6
	.word	0xca62c1d6
