/**********************************************************************
  Copyright (c) 2025 Institute of Software Chinese Academy of Sciences (ISCAS).

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
#define G v22
#define H v24

#define TT0 v0
#define TT1 v2
#define TT2 v4
#define TT3 v6
#define TT4 v8
#define TT5 v26
#define TT6 v28
#define TT7 v30

#define key_table t0
#define mh_segs t1
#define mh_segs_flag t2
#define P0 t3
#define P1 t4
#define P2 t5
#define P3 t6

#define mh_in_p a0
#define mh_digests_p  a1
#define mh_data_p	a2
#define loops a3

#define ROUND a5
#define TBL a6
#define FRAMESZ 4*8*16
#define SZ	4
#define SZ4	4*SZ

.macro PRORD reg, imm
	vsll.vi	TT4, \reg, (32-(\imm))
	vsrl.vi	\reg, \reg, \imm
	vor.vv	\reg, \reg, TT4
.endm

.macro PRORD_nd reg, src, imm
	vsll.vi	TT4, \src, (32-(\imm))
	vsrl.vi	\reg, \src, \imm
	vor.vv	\reg, \reg, TT4
.endm

.macro ROUND_00_15_R a, b, c, d, e, f, g, h, T1, i, data

	PRORD_nd	TT5, \e, (11-6)	# sig1: TT5 = (e >> 5)

	vxor.vv	TT7, \f, \g	# ch: TT7 = f^g
	vand.vv	TT7, TT7, \e		# ch: TT7 = (f^g)&e
	vxor.vv	TT7, TT7, \g		# TT7 = ch

	PRORD_nd	TT6, \e, 25		# sig1: TT6 = (e >> 25)
	addi	P0, \data, SZ4*(\i&0xf)
	add	P1, TBL, ROUND
	vle32.v	\T1, (P0)

	vle32.v	TT4, (P1)
	vadd.vv	\T1, \T1, TT4	# T1 = W + K
	vxor.vv	TT5, TT5, \e	# sig1: TT5 = e ^ (e >> 5)
	PRORD	TT5, 6		# sig1: TT5 = (e >> 6) ^ (e >> 11)
	vadd.vv	\h, \h, TT7	# h = h + ch
	PRORD_nd	TT7, \a, (13-2)	# sig0: TT7 = (a >> 11)
	vadd.vv	\h, \h, \T1	# h = h + ch + W + K
	vxor.vv	TT5, TT5, TT6	# TT5 = sigma1
	PRORD_nd	TT6, \a, 22	# sig0: TT6 = (a >> 22)
	vxor.vv	\T1, \a, \c	# maj: T1 = a^c
	addi	ROUND, ROUND, SZ4	# ROUND++
	vand.vv	\T1, \T1, \b	# maj: T1 = (a^c)&b
	vadd.vv	\h, \h, TT5

	vadd.vv	\d, \d, \h

	vxor.vv	TT7, TT7, \a	# sig0: TT7 = a ^ (a >> 11)
	PRORD	TT7, 2		# sig0: TT7 = (a >> 2) ^ (a >> 13)
	vxor.vv	TT7, TT7, TT6	# TT7 = sig0
	vand.vv	TT6, \a, \c	# maj: TT6 = a&c
	vor.vv	TT6, TT6, \T1	# TT6 = maj
	vadd.vv	\h, \h, TT6	# h = h + ch + W + K + maj
	vadd.vv	\h, \h, TT7	# h = h + ch + W + K + maj + sigma2

.endm

.macro ROUND_00_15_W a, b, c, d, e, f, g, h, T1, i, data

	PRORD_nd	TT5, \e, (11-6)	# sig1: TT5 = (e >> 5)

	vxor.vv	TT7, \f, \g	# ch: TT7 = f^g
	vand.vv	TT7, TT7, \e		# ch: TT7 = (f^g)&e
	vxor.vv	TT7, TT7, \g		# TT7 = ch

	PRORD_nd	TT6, \e, 25		# sig1: TT6 = (e >> 25)
	addi	P0, \data, SZ4*((\i)&0xf)
	add	P1, TBL, ROUND
	vse32.v	\T1, (P0)

	vle32.v	TT4, (P1)
	vadd.vv	\T1, \T1, TT4	# T1 = W + K
	vxor.vv	TT5, TT5, \e	# sig1: TT5 = e ^ (e >> 5)
	PRORD	TT5, 6		# sig1: TT5 = (e >> 6) ^ (e >> 11)
	vadd.vv	\h, \h, TT7	# h = h + ch
	PRORD_nd	TT7, \a, (13-2)	# sig0: TT7 = (a >> 11)
	vadd.vv	\h, \h, \T1	# h = h + ch + W + K
	vxor.vv	TT5, TT5, TT6	# TT5 = sigma1
	PRORD_nd	TT6, \a, 22	# sig0: TT6 = (a >> 22)
	vxor.vv	\T1, \a, \c	# maj: T1 = a^c
	addi	ROUND, ROUND, SZ4	# ROUND++
	vand.vv	\T1, \T1, \b	# maj: T1 = (a^c)&b
	vadd.vv	\h, \h, TT5

	vadd.vv	\d, \d, \h

	vxor.vv	TT7, TT7, \a	# sig0: TT7 = a ^ (a >> 11)
	PRORD	TT7, 2		# sig0: TT7 = (a >> 2) ^ (a >> 13)
	vxor.vv	TT7, TT7, TT6	# TT7 = sig0
	vand.vv	TT6, \a, \c	# maj: TT6 = a&c
	vor.vv	TT6, TT6, \T1	# TT6 = maj
	vadd.vv	\h, \h, TT6	# h = h + ch + W + K + maj
	vadd.vv	\h, \h, TT7	# h = h + ch + W + K + maj + sigma2

.endm

.macro ROUND_16_XX a, b, c, d, e, f, g, h, T1, i, data

	addi	P0, \data, SZ4*((\i-15)&0xf)
	addi	P1, \data, SZ4*((\i-2)&0xf)
	addi	P2, \data, SZ4*((\i-16)&0xf)
	addi	P3, \data, SZ4*((\i-7)&0xf)
	vle32.v	\T1, (P0)
	vle32.v	TT6, (P1)
	vmv.v.v	TT5, \T1
	PRORD	\T1, 18-7
	vmv.v.v	TT7, TT6
	PRORD	TT6, 19-17
	vxor.vv	\T1, \T1, TT5
	PRORD	\T1, 7
	vxor.vv	TT6, TT6, TT7
	PRORD	TT6, 17
	vsrl.vi	TT5, TT5, 3
	vxor.vv	\T1, \T1, TT5
	vsrl.vi	TT7, TT7, 10
	vxor.vv	TT6, TT6, TT7
	vle32.v	TT4, (P2)
	vadd.vv	\T1, \T1, TT4
	vle32.v	TT4, (P3)
	vadd.vv	TT6, TT6, TT4
	vadd.vv	\T1, \T1, TT6

	ROUND_00_15_W \a, \b, \c, \d, \e, \f, \g, \h, \T1, \i, \data

.endm

	.option arch, +v
	.global mh_sha256_block_rvv
	.type   mh_sha256_block_rvv, %function

mh_sha256_block_rvv:

	beqz loops, .done

	addi	sp, sp, -FRAMESZ

	la TBL, K_TABLE
	la key_table, GATHER_PATTERN

	vsetivli zero, 4, e32, m1, ta, ma

.set I, 0
.rept 8

	addi	P0, mh_digests_p, I*64 + 16*0
	addi	P1, mh_digests_p, I*64 + 16*1
	addi	P2, mh_digests_p, I*64 + 16*2
	addi	P3, mh_digests_p, I*64 + 16*3

	vle32.v	A, (P0)
	vle32.v	B, (P1)
	vle32.v	C, (P2)
	vle32.v	D, (P3)

	addi	P0, sp, I*64 + 16*0
	addi	P1, sp, I*64 + 16*1
	addi	P2, sp, I*64 + 16*2
	addi	P3, sp, I*64 + 16*3

	vse32.v	A, (P0)
	vse32.v	B, (P1)
	vse32.v	C, (P2)
	vse32.v	D, (P3)

.set I, I+1
.endr

.block_loop:

	vsetivli zero, 16, e8, m1, ta, ma
	vle8.v	TT7, (key_table)

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

	vrgather.vv	TT0, A, TT7
	vrgather.vv	TT1, B, TT7
	vrgather.vv	TT2, C, TT7
	vrgather.vv	TT3, D, TT7

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
	mv	ROUND, x0
	addi	mh_segs_flag, mh_segs, 64

	vsetivli zero, 4, e32, m1, ta, ma

.segs_loop:

	xor ROUND, ROUND, ROUND
	# Initialize digests
	addi	P0, mh_segs, 0*64
	addi	P1, mh_segs, 1*64
	addi	P2, mh_segs, 2*64
	addi	P3, mh_segs, 3*64
	vle32.v	A, (P0)
	vle32.v	B, (P1)
	vle32.v	C, (P2)
	vle32.v	D, (P3)
	addi	P0, mh_segs, 4*64
	addi	P1, mh_segs, 5*64
	addi	P2, mh_segs, 6*64
	addi	P3, mh_segs, 7*64
	vle32.v	E, (P0)
	vle32.v	F, (P1)
	vle32.v	G, (P2)
	vle32.v	H, (P3)

	ROUND_00_15_R	A, B, C, D, E, F, G, H, TT0, 0, mh_data_p
	ROUND_00_15_R	H, A, B, C, D, E, F, G, TT1, 1, mh_data_p
	ROUND_00_15_R	G, H, A, B, C, D, E, F, TT2, 2, mh_data_p
	ROUND_00_15_R	F, G, H, A, B, C, D, E, TT3, 3, mh_data_p

	ROUND_00_15_R	E, F, G, H, A, B, C, D, TT0, 4, mh_data_p
	ROUND_00_15_R	D, E, F, G, H, A, B, C, TT1, 5, mh_data_p
	ROUND_00_15_R	C, D, E, F, G, H, A, B, TT2, 6, mh_data_p
	ROUND_00_15_R	B, C, D, E, F, G, H, A, TT3, 7, mh_data_p

	ROUND_00_15_R	A, B, C, D, E, F, G, H, TT0, 8, mh_data_p
	ROUND_00_15_R	H, A, B, C, D, E, F, G, TT1, 9, mh_data_p
	ROUND_00_15_R	G, H, A, B, C, D, E, F, TT2, 10, mh_data_p
	ROUND_00_15_R	F, G, H, A, B, C, D, E, TT3, 11, mh_data_p

	ROUND_00_15_R	E, F, G, H, A, B, C, D, TT0, 12, mh_data_p
	ROUND_00_15_R	D, E, F, G, H, A, B, C, TT1, 13, mh_data_p
	ROUND_00_15_R	C, D, E, F, G, H, A, B, TT2, 14, mh_data_p
	ROUND_00_15_R	B, C, D, E, F, G, H, A, TT3, 15, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 16, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 17, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 18, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 19, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 20, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 21, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 22, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 23, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 24, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 25, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 26, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 27, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 28, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 29, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 30, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 31, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 32, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 33, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 34, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 35, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 36, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 37, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 38, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 39, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 40, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 41, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 42, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 43, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 44, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 45, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 46, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 47, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 48, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 49, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 50, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 51, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 52, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 53, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 54, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 55, mh_data_p

	ROUND_16_XX	A, B, C, D, E, F, G, H, TT0, 56, mh_data_p
	ROUND_16_XX	H, A, B, C, D, E, F, G, TT1, 57, mh_data_p
	ROUND_16_XX	G, H, A, B, C, D, E, F, TT2, 58, mh_data_p
	ROUND_16_XX	F, G, H, A, B, C, D, E, TT3, 59, mh_data_p

	ROUND_16_XX	E, F, G, H, A, B, C, D, TT0, 60, mh_data_p
	ROUND_16_XX	D, E, F, G, H, A, B, C, TT1, 61, mh_data_p
	ROUND_16_XX	C, D, E, F, G, H, A, B, TT2, 62, mh_data_p
	ROUND_16_XX	B, C, D, E, F, G, H, A, TT3, 63, mh_data_p

	# add old digest
	# write out digests
	addi	P0, mh_segs, 0*64
	addi	P1, mh_segs, 1*64
	addi	P2, mh_segs, 2*64
	addi	P3, mh_segs, 3*64
	vle32.v	TT0, (P0)
	vle32.v	TT1, (P1)
	vle32.v	TT2, (P2)
	vle32.v	TT3, (P3)
	vadd.vv	A, A, TT0
	vadd.vv	B, B, TT1
	vadd.vv	C, C, TT2
	vadd.vv	D, D, TT3
	vse32.v	A, (P0)
	vse32.v	B, (P1)
	vse32.v	C, (P2)
	vse32.v	D, (P3)

	addi	P0, mh_segs, 4*64
	addi	P1, mh_segs, 5*64
	addi	P2, mh_segs, 6*64
	addi	P3, mh_segs, 7*64
	vle32.v	TT0, (P0)
	vle32.v	TT1, (P1)
	vle32.v	TT2, (P2)
	vle32.v	TT3, (P3)
	vadd.vv	E, E, TT0
	vadd.vv	F, F, TT1
	vadd.vv	G, G, TT2
	vadd.vv	H, H, TT3
	vse32.v	E, (P0)
	vse32.v	F, (P1)
	vse32.v	G, (P2)
	vse32.v	H, (P3)

	addi	mh_data_p, mh_data_p, 256
	addi	mh_segs, mh_segs, 16
	bne mh_segs_flag, mh_segs, .segs_loop

	addi	mh_data_p, mh_data_p, -1024
	addi	mh_in_p, mh_in_p, 1024
	addi	loops, loops, -1
	bnez loops, .block_loop

.set I, 0
.rept 8

	addi	P0, sp, I*64 + 16*0
	addi	P1, sp, I*64 + 16*1
	addi	P2, sp, I*64 + 16*2
	addi	P3, sp, I*64 + 16*3

	vle32.v	A, (P0)
	vle32.v	B, (P1)
	vle32.v	C, (P2)
	vle32.v	D, (P3)

	addi	P0, mh_digests_p, I*64 + 16*0
	addi	P1, mh_digests_p, I*64 + 16*1
	addi	P2, mh_digests_p, I*64 + 16*2
	addi	P3, mh_digests_p, I*64 + 16*3

	vse32.v	A, (P0)
	vse32.v	B, (P1)
	vse32.v	C, (P2)
	vse32.v	D, (P3)

.set I, I+1
.endr

	addi	sp, sp, FRAMESZ

.done:
	ret

	.size mh_sha256_block_rvv, .-mh_sha256_block_rvv

	.section	.rodata
	.align	4

K_TABLE:
	.quad	0x428a2f98428a2f98, 0x428a2f98428a2f98
	.quad	0x7137449171374491, 0x7137449171374491
	.quad	0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf
	.quad	0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5
	.quad	0x3956c25b3956c25b, 0x3956c25b3956c25b
	.quad	0x59f111f159f111f1, 0x59f111f159f111f1
	.quad	0x923f82a4923f82a4, 0x923f82a4923f82a4
	.quad	0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5
	.quad	0xd807aa98d807aa98, 0xd807aa98d807aa98
	.quad	0x12835b0112835b01, 0x12835b0112835b01
	.quad	0x243185be243185be, 0x243185be243185be
	.quad	0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3
	.quad	0x72be5d7472be5d74, 0x72be5d7472be5d74
	.quad	0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe
	.quad	0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7
	.quad	0xc19bf174c19bf174, 0xc19bf174c19bf174
	.quad	0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1
	.quad	0xefbe4786efbe4786, 0xefbe4786efbe4786
	.quad	0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6
	.quad	0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc
	.quad	0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f
	.quad	0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa
	.quad	0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc
	.quad	0x76f988da76f988da, 0x76f988da76f988da
	.quad	0x983e5152983e5152, 0x983e5152983e5152
	.quad	0xa831c66da831c66d, 0xa831c66da831c66d
	.quad	0xb00327c8b00327c8, 0xb00327c8b00327c8
	.quad	0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7
	.quad	0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3
	.quad	0xd5a79147d5a79147, 0xd5a79147d5a79147
	.quad	0x06ca635106ca6351, 0x06ca635106ca6351
	.quad	0x1429296714292967, 0x1429296714292967
	.quad	0x27b70a8527b70a85, 0x27b70a8527b70a85
	.quad	0x2e1b21382e1b2138, 0x2e1b21382e1b2138
	.quad	0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc
	.quad	0x53380d1353380d13, 0x53380d1353380d13
	.quad	0x650a7354650a7354, 0x650a7354650a7354
	.quad	0x766a0abb766a0abb, 0x766a0abb766a0abb
	.quad	0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e
	.quad	0x92722c8592722c85, 0x92722c8592722c85
	.quad	0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1
	.quad	0xa81a664ba81a664b, 0xa81a664ba81a664b
	.quad	0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70
	.quad	0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3
	.quad	0xd192e819d192e819, 0xd192e819d192e819
	.quad	0xd6990624d6990624, 0xd6990624d6990624
	.quad	0xf40e3585f40e3585, 0xf40e3585f40e3585
	.quad	0x106aa070106aa070, 0x106aa070106aa070
	.quad	0x19a4c11619a4c116, 0x19a4c11619a4c116
	.quad	0x1e376c081e376c08, 0x1e376c081e376c08
	.quad	0x2748774c2748774c, 0x2748774c2748774c
	.quad	0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5
	.quad	0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3
	.quad	0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a
	.quad	0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f
	.quad	0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3
	.quad	0x748f82ee748f82ee, 0x748f82ee748f82ee
	.quad	0x78a5636f78a5636f, 0x78a5636f78a5636f
	.quad	0x84c8781484c87814, 0x84c8781484c87814
	.quad	0x8cc702088cc70208, 0x8cc702088cc70208
	.quad	0x90befffa90befffa, 0x90befffa90befffa
	.quad	0xa4506ceba4506ceb, 0xa4506ceba4506ceb
	.quad	0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7
	.quad	0xc67178f2c67178f2, 0xc67178f2c67178f2

GATHER_PATTERN:
	.quad 0x0405060700010203, 0x0c0d0e0f08090a0b

#endif
