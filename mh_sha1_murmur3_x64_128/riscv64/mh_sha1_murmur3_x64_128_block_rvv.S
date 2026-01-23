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
#define mh_segs t1
#define mh_segs_flag t2
#define P0 t3
#define P1 t4
#define P2 t5
#define P3 t6

#define mh_in_p a0
#define mh_digests_p a1
#define mh_data_p a2
#define mur_digest_p a3
#define loops a4
#define K1 a5
#define K2 a6
#define K3 a7
#define K4 s10

#define FRAMESZ 4*5*16
#define SZ 4
#define SZ4 4*SZ

#define mur_in_p s0
#define mur_hash1 s1
#define mur_hash2 s2
#define mur_data1 s3
#define mur_data2 s4
#define mur_c1_r s5
#define mur_c2_r s6
#define tmp s7
#define N1 s8
#define N2 s9

#define R1 (64-31)
#define R2 (64-33)
#define R3 (64-27)
#define R4 (64-31)
#define M  5
#define C1 0x87c37b91114253d5ULL
#define C2 0x4cf5ad432745937fULL

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

.macro SHA1_STEP_00_15 A, B, C, D, E, memW, key, MAGIC, data
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, \data, SZ4*(\memW)
	vle32.v	TT0, (P0)
	vadd.vv	\E, \E, TT0
	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

.macro SHA1_STEP_16_79_0 A, B, C, D, E, memW, key, MAGIC, data, TMP1, TMP2, TMP3
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, \data, SZ4*((\memW - 14) & 15)
	addi	P1, \data, SZ4*((\memW - 8) & 15)
	addi	P2, \data, SZ4*((\memW - 3) & 15)
	addi	P3, \data, SZ4*((\memW - 0) & 15)

	vle32.v	\TMP1, (P0)
	vle32.v	TT0, (P1)
	vle32.v	T, (P2)

	ld	mur_data1, 0(mur_in_p)
	ld	mur_data2, 8(mur_in_p)

	vxor.vv	\TMP3, \TMP3, \TMP1
	vxor.vv	\TMP3, \TMP3, TT0
	vxor.vv	\TMP3, \TMP3, T

	vsrl.vi	F, \TMP3, 31
	vsll.vi	\TMP3, \TMP3, 1
	vor.vv	F, F, \TMP3

	mul	mur_data1, mur_data1, mur_c1_r
	mul	mur_data2, mur_data2, mur_c2_r

	vse32.v	F, (P3)
	vadd.vv	\E, \E, F

	PROLD_nd T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

.macro SHA1_STEP_16_79_1 A, B, C, D, E, memW, key, MAGIC, data, TMP1, TMP2, TMP3
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, \data, SZ4*((\memW - 14) & 15)
	addi	P1, \data, SZ4*((\memW - 8) & 15)
	addi	P2, \data, SZ4*((\memW - 3) & 15)
	addi	P3, \data, SZ4*((\memW - 0) & 15)

	vle32.v	\TMP1, (P0)
	vle32.v	TT0, (P1)
	vle32.v	T, (P2)

	rori	mur_data1, mur_data1, R1
	rori	mur_data2, mur_data2, R2

	vxor.vv	\TMP3, \TMP3, \TMP1
	vxor.vv	\TMP3, \TMP3, TT0
	vxor.vv	\TMP3, \TMP3, T

	vsrl.vi	F, \TMP3, 31
	vsll.vi	\TMP3, \TMP3, 1
	vor.vv	F, F, \TMP3

	mul	mur_data1, mur_data1, mur_c2_r
	mul	mur_data2, mur_data2, mur_c1_r
	addi	mur_in_p, mur_in_p, 16

	vse32.v	F, (P3)
	vadd.vv	\E, \E, F

	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

.macro SHA1_STEP_16_79_2 A, B, C, D, E, memW, key, MAGIC, data, TMP1, TMP2, TMP3
	xor mur_hash1, mur_hash1, mur_data1
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, \data, SZ4*((\memW - 14) & 15)
	addi	P1, \data, SZ4*((\memW - 8) & 15)
	addi	P2, \data, SZ4*((\memW - 3) & 15)
	addi	P3, \data, SZ4*((\memW - 0) & 15)

	vle32.v	\TMP1, (P0)
	vle32.v	TT0, (P1)
	vle32.v	T, (P2)

	rori	mur_hash1, mur_hash1, R3

	vxor.vv	\TMP3, \TMP3, \TMP1
	vxor.vv	\TMP3, \TMP3, TT0
	vxor.vv	\TMP3, \TMP3, T

	vsrl.vi	F, \TMP3, 31
	vsll.vi	\TMP3, \TMP3, 1
	vor.vv	F, F, \TMP3

	add	mur_hash1, mur_hash1, mur_hash2

	vse32.v	F, (P3)
	vadd.vv	\E, \E, F

	sh2add	mur_hash1, mur_hash1, mur_hash1
	add	mur_hash1, mur_hash1, N1

	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm

.macro SHA1_STEP_16_79_3 A, B, C, D, E, memW, key, MAGIC, data, TMP1, TMP2, TMP3
	xor mur_hash2, mur_hash2, mur_data2
	vmv.v.x	TT0, \key
	vadd.vv	\E, \E, TT0

	addi	P0, \data, SZ4*((\memW - 14) & 15)
	addi	P1, \data, SZ4*((\memW - 8) & 15)
	addi	P2, \data, SZ4*((\memW - 3) & 15)
	addi	P3, \data, SZ4*((\memW - 0) & 15)

	vle32.v	\TMP1, (P0)
	vle32.v	TT0, (P1)
	vle32.v	T, (P2)

	rori	mur_hash2, mur_hash2, R4

	vxor.vv	\TMP3, \TMP3, \TMP1
	vxor.vv	\TMP3, \TMP3, TT0
	vxor.vv	\TMP3, \TMP3, T

	add	mur_hash2, mur_hash2, mur_hash1

	vsrl.vi	F, \TMP3, 31
	vsll.vi	\TMP3, \TMP3, 1
	vor.vv	F, F, \TMP3

	vse32.v	F, (P3)
	vadd.vv	\E, \E, F

	sh2add	mur_hash2, mur_hash2, mur_hash2
	add	mur_hash2, mur_hash2, N2

	PROLD_nd	T, 5, F, \A
	vadd.vv	\E, \E, T
	\MAGIC	\B, \C, \D
	PROLD	\B, 30, T
	vadd.vv	\E, \E, F
.endm


	.option arch, +v, +zba, +zbb
	.global mh_sha1_murmur3_x64_128_block_rvv
	.type   mh_sha1_murmur3_x64_128_block_rvv	, %function

mh_sha1_murmur3_x64_128_block_rvv:

	beqz loops, .done

	BACKUP_STACKS

	addi	sp, sp, -FRAMESZ

	li	K1, 0x5A827999
	li	K2, 0x6ED9EBA1
	li	K3, 0x8F1BBCDC
	li	K4, 0xCA62C1D6
	li	N1, 0x52dce729U
	li	N2, 0x38495ab5U
	li	mur_c1_r, C1
	li	mur_c2_r, C2

	la	key_table, GATHER_PATTERN

	vsetivli zero, 16, e8, m1, ta, ma

.set I, 0
.rept 5

	addi	P0, mh_digests_p, I*64 + 16*0
	addi	P1, mh_digests_p, I*64 + 16*1
	addi	P2, mh_digests_p, I*64 + 16*2
	addi	P3, mh_digests_p, I*64 + 16*3

	vle8.v	A, (P0)
	vle8.v	B, (P1)
	vle8.v	C, (P2)
	vle8.v	D, (P3)

	addi	P0, sp, I*64 + 16*0
	addi	P1, sp, I*64 + 16*1
	addi	P2, sp, I*64 + 16*2
	addi	P3, sp, I*64 + 16*3

	vse8.v	A, (P0)
	vse8.v	B, (P1)
	vse8.v	C, (P2)
	vse8.v	D, (P3)

.set I, I+1
.endr

	mv	mur_in_p, mh_in_p
	ld	mur_hash1, (mur_digest_p)
	ld	mur_hash2, 8(mur_digest_p)

.block_loop:

	vsetivli zero, 16, e8, m1, ta, ma
	vle8.v	E, (key_table)

.set I, 0
.rept 16

	addi	P0, mh_in_p, I*64+0*16
	addi	P1, mh_in_p, I*64+1*16
	addi	P2, mh_in_p, I*64+2*16
	addi	P3, mh_in_p, I*64+3*16

	vle8.v	A, (P0)
	vle8.v	B, (P1)
	vle8.v	C, (P2)
	vle8.v	D, (P3)

	vrgather.vv	TT0, A, E
	vrgather.vv	TT1, B, E
	vrgather.vv	TT2, C, E
	vrgather.vv	TT3, D, E

	addi	P0, mh_data_p, I*16+0*256
	addi	P1, mh_data_p, I*16+1*256
	addi	P2, mh_data_p, I*16+2*256
	addi	P3, mh_data_p, I*16+3*256

	vse8.v	TT0, (P0)
	vse8.v	TT1, (P1)
	vse8.v	TT2, (P2)
	vse8.v	TT3, (P3)

.set I, I+1
.endr

	mv	mh_segs, sp
	addi	mh_segs_flag, mh_segs, 64

	vsetivli zero, 4, e32, m1, ta, ma

.segs_loop:

	# Initialize digests
	addi	P0, mh_segs, 0*64
	addi	P1, mh_segs, 1*64
	addi	P2, mh_segs, 2*64
	vle32.v	A, (P0)
	vle32.v	B, (P1)
	vle32.v	C, (P2)

	addi	P1, mh_segs, 3*64
	addi	P2, mh_segs, 4*64
	vle32.v	D, (P1)
	vle32.v	E, (P2)

	vmv.v.v	AA, A
	vmv.v.v	BB, B
	vmv.v.v	CC, C
	vmv.v.v	DD, D
	vmv.v.v	EE, E

.segs_loop_inner:

	SHA1_STEP_00_15	A, B, C, D, E, 0, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	E, A, B, C, D, 1, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	D, E, A, B, C, 2, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	C, D, E, A, B, 3, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	B, C, D, E, A, 4, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	A, B, C, D, E, 5, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	E, A, B, C, D, 6, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	D, E, A, B, C, 7, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	C, D, E, A, B, 8, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	B, C, D, E, A, 9, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	A, B, C, D, E, 10, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	E, A, B, C, D, 11, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	D, E, A, B, C, 12, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	C, D, E, A, B, 13, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	B, C, D, E, A, 14, K1, MAGIC_F0, mh_data_p
	SHA1_STEP_00_15	A, B, C, D, E, 15, K1, MAGIC_F0, mh_data_p

	addi	P0, mh_data_p, ((16 - 16) & 15) * 16
	addi	P1, mh_data_p, ((16 - 15) & 15) * 16
	vle32.v	TT3, (P0)
	vle32.v	TT2, (P1)

	SHA1_STEP_16_79_0	E, A, B, C, D, 16, K1, MAGIC_F0, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	D, E, A, B, C, 17, K1, MAGIC_F0, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	C, D, E, A, B, 18, K1, MAGIC_F0, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	B, C, D, E, A, 19, K1, MAGIC_F0, mh_data_p, TT1, TT2, TT3

	SHA1_STEP_16_79_0	A, B, C, D, E, 20, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_1	E, A, B, C, D, 21, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_2	D, E, A, B, C, 22, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_3	C, D, E, A, B, 23, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_0	B, C, D, E, A, 24, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_1	A, B, C, D, E, 25, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_2	E, A, B, C, D, 26, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_3	D, E, A, B, C, 27, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_0	C, D, E, A, B, 28, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	B, C, D, E, A, 29, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	A, B, C, D, E, 30, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	E, A, B, C, D, 31, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_0	D, E, A, B, C, 32, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_1	C, D, E, A, B, 33, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_2	B, C, D, E, A, 34, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_3	A, B, C, D, E, 35, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_0	E, A, B, C, D, 36, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_1	D, E, A, B, C, 37, K2, MAGIC_F1, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_2	C, D, E, A, B, 38, K2, MAGIC_F1, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_3	B, C, D, E, A, 39, K2, MAGIC_F1, mh_data_p, TT2, TT3, TT1

	SHA1_STEP_16_79_0	A, B, C, D, E, 40, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	E, A, B, C, D, 41, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	D, E, A, B, C, 42, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	C, D, E, A, B, 43, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_0	B, C, D, E, A, 44, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_1	A, B, C, D, E, 45, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_2	E, A, B, C, D, 46, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_3	D, E, A, B, C, 47, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_0	C, D, E, A, B, 48, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_1	B, C, D, E, A, 49, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_2	A, B, C, D, E, 50, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_3	E, A, B, C, D, 51, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_0	D, E, A, B, C, 52, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	C, D, E, A, B, 53, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	B, C, D, E, A, 54, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	A, B, C, D, E, 55, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_0	E, A, B, C, D, 56, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_1	D, E, A, B, C, 57, K3, MAGIC_F2, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_2	C, D, E, A, B, 58, K3, MAGIC_F2, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_3	B, C, D, E, A, 59, K3, MAGIC_F2, mh_data_p, TT3, TT1, TT2

	SHA1_STEP_16_79_0	A, B, C, D, E, 60, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_1	E, A, B, C, D, 61, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_2	D, E, A, B, C, 62, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_3	C, D, E, A, B, 63, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_0	B, C, D, E, A, 64, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	A, B, C, D, E, 65, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	E, A, B, C, D, 66, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	D, E, A, B, C, 67, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_0	C, D, E, A, B, 68, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_1	B, C, D, E, A, 69, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_2	A, B, C, D, E, 70, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_3	E, A, B, C, D, 71, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_0	D, E, A, B, C, 72, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_1	C, D, E, A, B, 73, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_2	B, C, D, E, A, 74, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_3	A, B, C, D, E, 75, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_0	E, A, B, C, D, 76, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3
	SHA1_STEP_16_79_1	D, E, A, B, C, 77, K4, MAGIC_F3, mh_data_p, TT3, TT1, TT2
	SHA1_STEP_16_79_2	C, D, E, A, B, 78, K4, MAGIC_F3, mh_data_p, TT2, TT3, TT1
	SHA1_STEP_16_79_3	B, C, D, E, A, 79, K4, MAGIC_F3, mh_data_p, TT1, TT2, TT3

	# add old digest
	# write out digests
	vadd.vv	A, A, AA
	vadd.vv	B, B, BB
	vadd.vv	C, C, CC
	vadd.vv	D, D, DD
	vadd.vv	E, E, EE

	addi	P0, mh_segs, 0*64
	addi	P1, mh_segs, 1*64
	addi	P2, mh_segs, 2*64
	vse32.v	A, (P0)
	vse32.v	B, (P1)
	vse32.v	C, (P2)

	addi	P1, mh_segs, 3*64
	addi	P2, mh_segs, 4*64
	vse32.v	D, (P1)
	vse32.v	E, (P2)

	addi	mh_data_p, mh_data_p, 256
	addi	mh_segs, mh_segs, 16
	bne mh_segs_flag, mh_segs, .segs_loop

	addi	mh_data_p, mh_data_p, -1024
	addi	mh_in_p, mh_in_p, 1024
	addi	loops, loops, -1
	bnez loops, .block_loop

	sd	mur_hash1, (mur_digest_p)
	sd	mur_hash2, 8(mur_digest_p)

	vsetivli zero, 16, e8, m1, ta, ma

.set I, 0
.rept 5

	addi	P0, sp, I*64 + 16*0
	addi	P1, sp, I*64 + 16*1
	addi	P2, sp, I*64 + 16*2
	addi	P3, sp, I*64 + 16*3

	vle8.v	A, (P0)
	vle8.v	B, (P1)
	vle8.v	C, (P2)
	vle8.v	D, (P3)

	addi	P0, mh_digests_p, I*64 + 16*0
	addi	P1, mh_digests_p, I*64 + 16*1
	addi	P2, mh_digests_p, I*64 + 16*2
	addi	P3, mh_digests_p, I*64 + 16*3

	vse8.v	A, (P0)
	vse8.v	B, (P1)
	vse8.v	C, (P2)
	vse8.v	D, (P3)

.set I, I+1
.endr

	addi	sp, sp, FRAMESZ

	RESTORE_STACKS

.done:
	ret

	.size mh_sha1_murmur3_x64_128_block_rvv	, .-mh_sha1_murmur3_x64_128_block_rvv

	.section	.rodata
	.align	4

GATHER_PATTERN:
	.quad 0x0405060700010203, 0x0c0d0e0f08090a0b

#endif
