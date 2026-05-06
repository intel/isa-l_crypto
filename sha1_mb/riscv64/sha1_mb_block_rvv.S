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

#if HAVE_RVV

#define A v10
#define B v12
#define C v14
#define D v16
#define E v18
#define F v20
#define T v22
#define TT0 v24
#define TT1 v26
#define TT2 v28
#define TT3 v30

#define AA v0
#define BB v2
#define CC v4
#define DD v6
#define EE v8

#define key_table t0
#define P0 t1
#define P1 t2
#define P2 t3
#define P3 t4
#define P4 t5
#define P5 t6


#define loops a1
#define K1 a4
#define K2 a5
#define K3 a6
#define K4 a7

#define inp0 s0
#define inp1 s1
#define inp2 s2
#define inp3 s3
#define transpose_ptr_inp0 s4
#define transpose_ptr_inp1 s5
#define transpose_ptr_inp2 s6
#define transpose_ptr_inp3 s7
#define transpose_ptr_out1 s8
#define transpose_ptr_out2 s9
#define transpose_ptr_out3 s10
#define ptrdiff_t s11

#define FRAMESZ 16*16
#define SZ 4
#define SZ4 4*SZ
#define _data_ptr 0x140

.macro BACKUP_STACKS
	addi sp, sp, -96

	sd s0, 0(sp)
	sd s1, 8(sp)
	sd s2, 16(sp)
	sd s3, 24(sp)
	sd s4, 32(sp)
	sd s5, 40(sp)
	sd s6, 48(sp)
	sd s7, 56(sp)
	sd s8, 64(sp)
	sd s9, 72(sp)
	sd s10, 80(sp)
	sd s11, 88(sp)
.endm

.macro RESTORE_STACKS
	ld s0, 0(sp)
	ld s1, 8(sp)
	ld s2, 16(sp)
	ld s3, 24(sp)
	ld s4, 32(sp)
	ld s5, 40(sp)
	ld s6, 48(sp)
	ld s7, 56(sp)
	ld s8, 64(sp)
	ld s9, 72(sp)
	ld s10, 80(sp)
	ld s11, 88(sp)

	addi sp, sp, 96
.endm

.macro TRANSPOSE R0, R1, R2, R3
	vse32.v	\R0, (transpose_ptr_inp0)
	vse32.v	\R1, (transpose_ptr_inp1)
	vse32.v	\R2, (transpose_ptr_inp2)
	vse32.v	\R3, (transpose_ptr_inp3)
	vlse32.v	\R0, (transpose_ptr_inp0), ptrdiff_t
	vlse32.v	\R1, (transpose_ptr_out1), ptrdiff_t
	vlse32.v	\R2, (transpose_ptr_out2), ptrdiff_t
	vlse32.v	\R3, (transpose_ptr_out3), ptrdiff_t
.endm

.macro MAGIC_F0 B, C, D
	vxor.vv	F, \C, \D
	vand.vv	F, F, \B
	vxor.vv	F, F, \D
.endm

.macro MAGIC_F1 B, C, D
	vxor.vv	F, \D, \C
	vxor.vv	F, F, \B
.endm

.macro MAGIC_F2 B, C, D
	vor.vv	F, \B, \C
	vand.vv	T, \B, \C
	vand.vv	F, F, \D
	vor.vv	F, F, T
.endm

.macro MAGIC_F3 B, C, D
	MAGIC_F1 \B, \C, \D
.endm

.macro PROLD reg, imm, tmp
	vsrl.vi	\tmp, \reg, (32-(\imm))
	vsll.vi	\reg, \reg, \imm
	vor.vv	\reg, \reg, \tmp
.endm

.macro PROLD_nd reg, imm, tmp, src
	vsrl.vi	\tmp, \src, (32-(\imm))
	vsll.vi	\reg, \src, \imm
	vor.vv	\reg, \reg, \tmp
.endm

.macro SHA1_STEP_00_15 A, B, C, D, E, memW, key, MAGIC
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, sp, SZ4*(\memW * 1)
	vle32.v	TT0, (P0)
	vadd.vv	\E, \E, TT0
	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

.macro SHA1_STEP_16_79 A, B, C, D, E, memW, key, MAGIC, TMP1, TMP2, TMP3
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, sp, SZ4*((\memW - 14) & 15)
	addi	P1, sp, SZ4*((\memW - 8) & 15)
	addi	P2, sp, SZ4*((\memW - 3) & 15)
	addi	P3, sp, SZ4*((\memW - 0) & 15)

	vle32.v	\TMP1, (P0)
	vle32.v	TT0, (P1)
	vle32.v	T, (P2)

	vxor.vv	\TMP3, \TMP3, \TMP1
	vxor.vv	\TMP3, \TMP3, TT0
	vxor.vv	\TMP3, \TMP3, T

	vsrl.vi	F, \TMP3, 31
	vsll.vi	\TMP3, \TMP3, 1
	vor.vv	F, F, \TMP3

	vse32.v	F, (P3)
	vadd.vv	\E, \E, F

	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

	.option arch, +v
	.global sha1_mb_rvv_x4
	.type   sha1_mb_rvv_x4, %function

sha1_mb_rvv_x4:

	beqz loops, .done

	BACKUP_STACKS

	addi	sp, sp, -(FRAMESZ+128)

	li	K1, 0x5A827999
	li	K2, 0x6ED9EBA1
	li	K3, 0x8F1BBCDC
	li	K4, 0xCA62C1D6

	la	key_table, GATHER_PATTERN

	vsetivli zero, 4, e32, m1, ta, ma

	addi P1, a0, 64*1
	addi P2, a0, 64*2
	addi P3, a0, 64*3
	addi P4, a0, 64*4

	vle32.v	A, (a0)
	vle32.v	B, (P1)
	vle32.v	C, (P2)
	vle32.v	D, (P3)
	vle32.v	E, (P4)

	ld	inp0, _data_ptr + 0*8(a0)
	ld	inp1, _data_ptr + 1*8(a0)
	ld	inp2, _data_ptr + 2*8(a0)
	ld	inp3, _data_ptr + 3*8(a0)

	# add sp for transpose data pointer
	addi	transpose_ptr_inp0, sp, FRAMESZ + 0*16
	addi	transpose_ptr_inp1, sp, FRAMESZ + 1*16
	addi	transpose_ptr_inp2, sp, FRAMESZ + 2*16
	addi	transpose_ptr_inp3, sp, FRAMESZ + 3*16
	addi	transpose_ptr_out1, sp, FRAMESZ + 1*4
	addi	transpose_ptr_out2, sp, FRAMESZ + 2*4
	addi	transpose_ptr_out3, sp, FRAMESZ + 3*4
	li	ptrdiff_t, 16

.block_loop:

	vsetivli zero, 16, e8, m1, ta, ma
	vle8.v	EE, (key_table)

.set I, 0
.rept 4

	vsetivli zero, 4, e32, m1, ta, ma

	# Load each lane one at a time, store to transpose scratch area
	vle32.v	AA, (inp0)
	addi	inp0, inp0, 16
	vse32.v	AA, (transpose_ptr_inp0)

	vle32.v	AA, (inp1)
	addi	inp1, inp1, 16
	vse32.v	AA, (transpose_ptr_inp1)

	vle32.v	AA, (inp2)
	addi	inp2, inp2, 16
	vse32.v	AA, (transpose_ptr_inp2)

	vle32.v	AA, (inp3)
	addi	inp3, inp3, 16
	vse32.v	AA, (transpose_ptr_inp3)

	# Strided loads for 4x4 transpose
	vlse32.v	AA, (transpose_ptr_inp0), ptrdiff_t
	vlse32.v	BB, (transpose_ptr_out1), ptrdiff_t
	vlse32.v	CC, (transpose_ptr_out2), ptrdiff_t
	vlse32.v	DD, (transpose_ptr_out3), ptrdiff_t

	# Byte-swap (big-endian to little-endian)
	vsetivli zero, 16, e8, m1, ta, ma

	vrgather.vv	TT0, AA, EE
	vrgather.vv	TT1, BB, EE
	vrgather.vv	TT2, CC, EE
	vrgather.vv	TT3, DD, EE

	addi	P0, sp, (I*4+0)*16
	addi	P1, sp, (I*4+1)*16
	addi	P2, sp, (I*4+2)*16
	addi	P3, sp, (I*4+3)*16

	vse8.v	TT0, (P0)
	vse8.v	TT1, (P1)
	vse8.v	TT2, (P2)
	vse8.v	TT3, (P3)

.set I, I+1
.endr
	vsetivli zero, 4, e32, m1, ta, ma

.segs_loop:

	vmv.v.v	AA, A
	vmv.v.v	BB, B
	vmv.v.v	CC, C
	vmv.v.v	DD, D
	vmv.v.v	EE, E

	SHA1_STEP_00_15	A, B, C, D, E, 0, K1, MAGIC_F0
	SHA1_STEP_00_15	E, A, B, C, D, 1, K1, MAGIC_F0
	SHA1_STEP_00_15	D, E, A, B, C, 2, K1, MAGIC_F0
	SHA1_STEP_00_15	C, D, E, A, B, 3, K1, MAGIC_F0
	SHA1_STEP_00_15	B, C, D, E, A, 4, K1, MAGIC_F0
	SHA1_STEP_00_15	A, B, C, D, E, 5, K1, MAGIC_F0
	SHA1_STEP_00_15	E, A, B, C, D, 6, K1, MAGIC_F0
	SHA1_STEP_00_15	D, E, A, B, C, 7, K1, MAGIC_F0
	SHA1_STEP_00_15	C, D, E, A, B, 8, K1, MAGIC_F0
	SHA1_STEP_00_15	B, C, D, E, A, 9, K1, MAGIC_F0
	SHA1_STEP_00_15	A, B, C, D, E, 10, K1, MAGIC_F0
	SHA1_STEP_00_15	E, A, B, C, D, 11, K1, MAGIC_F0
	SHA1_STEP_00_15	D, E, A, B, C, 12, K1, MAGIC_F0
	SHA1_STEP_00_15	C, D, E, A, B, 13, K1, MAGIC_F0
	SHA1_STEP_00_15	B, C, D, E, A, 14, K1, MAGIC_F0
	SHA1_STEP_00_15	A, B, C, D, E, 15, K1, MAGIC_F0

	addi	P0, sp, ((16 - 16) & 15) * 16
	addi	P1, sp, ((16 - 15) & 15) * 16
	vle32.v	TT3, (P0)
	vle32.v	TT2, (P1)

	SHA1_STEP_16_79	E, A, B, C, D, 16, K1, MAGIC_F0, TT1, TT2, TT3
	SHA1_STEP_16_79	D, E, A, B, C, 17, K1, MAGIC_F0, TT3, TT1, TT2
	SHA1_STEP_16_79	C, D, E, A, B, 18, K1, MAGIC_F0, TT2, TT3, TT1
	SHA1_STEP_16_79	B, C, D, E, A, 19, K1, MAGIC_F0, TT1, TT2, TT3

	SHA1_STEP_16_79	A, B, C, D, E, 20, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	E, A, B, C, D, 21, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	D, E, A, B, C, 22, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	C, D, E, A, B, 23, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	B, C, D, E, A, 24, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	A, B, C, D, E, 25, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	E, A, B, C, D, 26, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	D, E, A, B, C, 27, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	C, D, E, A, B, 28, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	B, C, D, E, A, 29, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	A, B, C, D, E, 30, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	E, A, B, C, D, 31, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	D, E, A, B, C, 32, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	C, D, E, A, B, 33, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	B, C, D, E, A, 34, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	A, B, C, D, E, 35, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	E, A, B, C, D, 36, K2, MAGIC_F1, TT2, TT3, TT1
	SHA1_STEP_16_79	D, E, A, B, C, 37, K2, MAGIC_F1, TT1, TT2, TT3
	SHA1_STEP_16_79	C, D, E, A, B, 38, K2, MAGIC_F1, TT3, TT1, TT2
	SHA1_STEP_16_79	B, C, D, E, A, 39, K2, MAGIC_F1, TT2, TT3, TT1

	SHA1_STEP_16_79	A, B, C, D, E, 40, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	E, A, B, C, D, 41, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	D, E, A, B, C, 42, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	C, D, E, A, B, 43, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	B, C, D, E, A, 44, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	A, B, C, D, E, 45, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	E, A, B, C, D, 46, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	D, E, A, B, C, 47, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	C, D, E, A, B, 48, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	B, C, D, E, A, 49, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	A, B, C, D, E, 50, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	E, A, B, C, D, 51, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	D, E, A, B, C, 52, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	C, D, E, A, B, 53, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	B, C, D, E, A, 54, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	A, B, C, D, E, 55, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	E, A, B, C, D, 56, K3, MAGIC_F2, TT3, TT1, TT2
	SHA1_STEP_16_79	D, E, A, B, C, 57, K3, MAGIC_F2, TT2, TT3, TT1
	SHA1_STEP_16_79	C, D, E, A, B, 58, K3, MAGIC_F2, TT1, TT2, TT3
	SHA1_STEP_16_79	B, C, D, E, A, 59, K3, MAGIC_F2, TT3, TT1, TT2

	SHA1_STEP_16_79	A, B, C, D, E, 60, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	E, A, B, C, D, 61, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	D, E, A, B, C, 62, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	C, D, E, A, B, 63, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	B, C, D, E, A, 64, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	A, B, C, D, E, 65, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	E, A, B, C, D, 66, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	D, E, A, B, C, 67, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	C, D, E, A, B, 68, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	B, C, D, E, A, 69, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	A, B, C, D, E, 70, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	E, A, B, C, D, 71, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	D, E, A, B, C, 72, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	C, D, E, A, B, 73, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	B, C, D, E, A, 74, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	A, B, C, D, E, 75, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	E, A, B, C, D, 76, K4, MAGIC_F3, TT1, TT2, TT3
	SHA1_STEP_16_79	D, E, A, B, C, 77, K4, MAGIC_F3, TT3, TT1, TT2
	SHA1_STEP_16_79	C, D, E, A, B, 78, K4, MAGIC_F3, TT2, TT3, TT1
	SHA1_STEP_16_79	B, C, D, E, A, 79, K4, MAGIC_F3, TT1, TT2, TT3

	# add old digest
	# write out digests
	vadd.vv	A, A, AA
	vadd.vv	B, B, BB
	vadd.vv	C, C, CC
	vadd.vv	D, D, DD
	vadd.vv	E, E, EE

	addi	loops, loops, -1
	bnez loops, .block_loop

	addi	P0, a0, 0*64
	addi	P1, a0, 1*64
	addi	P2, a0, 2*64
	vse32.v	A, (P0)
	vse32.v	B, (P1)
	vse32.v	C, (P2)

	addi	P1, a0, 3*64
	addi	P2, a0, 4*64
	vse32.v	D, (P1)
	vse32.v	E, (P2)

	sd	inp0, _data_ptr + 0*8(a0)
	sd	inp1, _data_ptr + 1*8(a0)
	sd	inp2, _data_ptr + 2*8(a0)
	sd	inp3, _data_ptr + 3*8(a0)

	addi	sp, sp, (FRAMESZ+128)

	RESTORE_STACKS

.done:
	ret

	.size sha1_mb_rvv_x4, .-sha1_mb_rvv_x4

	.section	.rodata
	.align	4


GATHER_PATTERN:
	.quad 0x0405060700010203, 0x0c0d0e0f08090a0b

#endif
