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

#define WA s0
#define WB s1
#define WC s2
#define WD s3
#define WE s4

#define AA s5
#define BB s6
#define CC s7
#define DD s8
#define EE s9

#define DGST s10

#define WK t3

#define T0 t0
#define T1 t1
#define T2 t2
#define T4 t4
#define T5 t5

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

#define FRAMESZ 64
#define FRAMESAVES 64

.macro BACKUP_STACKS
	addi	sp, sp, -(FRAMESZ + 12*8)
	sd	ra,  FRAMESAVES+ 0(sp)
	sd	s0,  FRAMESAVES+ 8(sp)
	sd	s1,  FRAMESAVES+16(sp)
	sd	s2,  FRAMESAVES+24(sp)
	sd	s3,  FRAMESAVES+32(sp)
	sd	s4,  FRAMESAVES+40(sp)
	sd	s5,  FRAMESAVES+48(sp)
	sd	s6,  FRAMESAVES+56(sp)
	sd	s7,  FRAMESAVES+64(sp)
	sd	s8,  FRAMESAVES+72(sp)
	sd	s9,  FRAMESAVES+80(sp)
	sd	s10, FRAMESAVES+88(sp)
.endm

.macro RESTORE_STACKS
	ld	ra,  FRAMESAVES+ 0(sp)
	ld	s0,  FRAMESAVES+ 8(sp)
	ld	s1,  FRAMESAVES+16(sp)
	ld	s2,  FRAMESAVES+24(sp)
	ld	s3,  FRAMESAVES+32(sp)
	ld	s4,  FRAMESAVES+40(sp)
	ld	s5,  FRAMESAVES+48(sp)
	ld	s6,  FRAMESAVES+56(sp)
	ld	s7,  FRAMESAVES+64(sp)
	ld	s8,  FRAMESAVES+72(sp)
	ld	s9,  FRAMESAVES+80(sp)
	ld	s10, FRAMESAVES+88(sp)
	addi	sp, sp, (FRAMESZ + 12*8)
.endm

.macro BSWAP reg
	rev8	\reg, \reg
	srli	\reg, \reg, 32
.endm

.macro ROL1 reg
	roriw	\reg, \reg, 31
.endm

# F0 = D ^ (B & (C ^ D))
.macro MAGIC_F0
	xor	T0, WC, WD
	and	T0, WB, T0
	xor	T0, WD, T0
.endm

# F1 = B ^ C ^ D
.macro MAGIC_F1
	xor	T0, WB, WC
	xor	T0, T0, WD
.endm

# F2 = (B & C) | (D & (B | C))
.macro MAGIC_F2
	and	T0, WB, WC
	or	T1, WB, WC
	and	T1, WD, T1
	or	T0, T0, T1
.endm

.macro MAGIC_F3
	MAGIC_F1
.endm

.macro SHA1_ROUND_BODY
	# T2 = ROL5(WA)
	roriw	T2, WA, 27

	# T2 = ROL5(A) + E + K + W[i] + F
	addw	T2, T2, WE
	addw	T2, T2, WK
	addw	T2, T2, T4
	addw	T2, T2, T0

	# T0 = ROL30(WB) = new C
	roriw	T0, WB, 2

	# rotate state
	mv	WE, WD
	mv	WD, WC
	mv	WC, T0
	mv	WB, WA
	mv	WA, T2
.endm

.macro SHA1_STEP_00_15 round, MAGIC
	lwu	T4, ((\round) * 4)(a0)
	BSWAP	T4
	sw	T4, ((\round & 15) * 4)(sp)

	\MAGIC
	SHA1_ROUND_BODY
.endm

.macro SHA1_STEP_16_79 round, MAGIC
	lwu	T4, (((\round - 16) & 15) * 4)(sp)
	lwu	T5, (((\round - 14) & 15) * 4)(sp)
	xor	T4, T4, T5
	lwu	T5, (((\round -  8) & 15) * 4)(sp)
	xor	T4, T4, T5
	lwu	T5, (((\round -  3) & 15) * 4)(sp)
	xor	T4, T4, T5
	ROL1	T4
	sw	T4, ((\round & 15) * 4)(sp)

	\MAGIC
	SHA1_ROUND_BODY
.endm

	.text
	.option arch, +zbb
	.global	sha1_riscv64_x1
	.type	sha1_riscv64_x1, %function

sha1_riscv64_x1:

	beqz	a1, .done

	BACKUP_STACKS

	mv	DGST, a2

	lwu	WA,  0(a2)
	lwu	WB,  4(a2)
	lwu	WC,  8(a2)
	lwu	WD, 12(a2)
	lwu	WE, 16(a2)

.block_loop:
	mv	AA, WA
	mv	BB, WB
	mv	CC, WC
	mv	DD, WD
	mv	EE, WE

	# rounds 0-19
	li	WK, K1
	SHA1_STEP_00_15	 0, MAGIC_F0
	SHA1_STEP_00_15	 1, MAGIC_F0
	SHA1_STEP_00_15	 2, MAGIC_F0
	SHA1_STEP_00_15	 3, MAGIC_F0
	SHA1_STEP_00_15	 4, MAGIC_F0
	SHA1_STEP_00_15	 5, MAGIC_F0
	SHA1_STEP_00_15	 6, MAGIC_F0
	SHA1_STEP_00_15	 7, MAGIC_F0
	SHA1_STEP_00_15	 8, MAGIC_F0
	SHA1_STEP_00_15	 9, MAGIC_F0
	SHA1_STEP_00_15	10, MAGIC_F0
	SHA1_STEP_00_15	11, MAGIC_F0
	SHA1_STEP_00_15	12, MAGIC_F0
	SHA1_STEP_00_15	13, MAGIC_F0
	SHA1_STEP_00_15	14, MAGIC_F0
	SHA1_STEP_00_15	15, MAGIC_F0

	addi	a0, a0, 64

	SHA1_STEP_16_79	16, MAGIC_F0
	SHA1_STEP_16_79	17, MAGIC_F0
	SHA1_STEP_16_79	18, MAGIC_F0
	SHA1_STEP_16_79	19, MAGIC_F0

	# rounds 20-39
	li	WK, K2
	SHA1_STEP_16_79	20, MAGIC_F1
	SHA1_STEP_16_79	21, MAGIC_F1
	SHA1_STEP_16_79	22, MAGIC_F1
	SHA1_STEP_16_79	23, MAGIC_F1
	SHA1_STEP_16_79	24, MAGIC_F1
	SHA1_STEP_16_79	25, MAGIC_F1
	SHA1_STEP_16_79	26, MAGIC_F1
	SHA1_STEP_16_79	27, MAGIC_F1
	SHA1_STEP_16_79	28, MAGIC_F1
	SHA1_STEP_16_79	29, MAGIC_F1
	SHA1_STEP_16_79	30, MAGIC_F1
	SHA1_STEP_16_79	31, MAGIC_F1
	SHA1_STEP_16_79	32, MAGIC_F1
	SHA1_STEP_16_79	33, MAGIC_F1
	SHA1_STEP_16_79	34, MAGIC_F1
	SHA1_STEP_16_79	35, MAGIC_F1
	SHA1_STEP_16_79	36, MAGIC_F1
	SHA1_STEP_16_79	37, MAGIC_F1
	SHA1_STEP_16_79	38, MAGIC_F1
	SHA1_STEP_16_79	39, MAGIC_F1

	# rounds 40-59
	li	WK, K3
	SHA1_STEP_16_79	40, MAGIC_F2
	SHA1_STEP_16_79	41, MAGIC_F2
	SHA1_STEP_16_79	42, MAGIC_F2
	SHA1_STEP_16_79	43, MAGIC_F2
	SHA1_STEP_16_79	44, MAGIC_F2
	SHA1_STEP_16_79	45, MAGIC_F2
	SHA1_STEP_16_79	46, MAGIC_F2
	SHA1_STEP_16_79	47, MAGIC_F2
	SHA1_STEP_16_79	48, MAGIC_F2
	SHA1_STEP_16_79	49, MAGIC_F2
	SHA1_STEP_16_79	50, MAGIC_F2
	SHA1_STEP_16_79	51, MAGIC_F2
	SHA1_STEP_16_79	52, MAGIC_F2
	SHA1_STEP_16_79	53, MAGIC_F2
	SHA1_STEP_16_79	54, MAGIC_F2
	SHA1_STEP_16_79	55, MAGIC_F2
	SHA1_STEP_16_79	56, MAGIC_F2
	SHA1_STEP_16_79	57, MAGIC_F2
	SHA1_STEP_16_79	58, MAGIC_F2
	SHA1_STEP_16_79	59, MAGIC_F2

	# rounds 60-79
	li	WK, K4
	SHA1_STEP_16_79	60, MAGIC_F3
	SHA1_STEP_16_79	61, MAGIC_F3
	SHA1_STEP_16_79	62, MAGIC_F3
	SHA1_STEP_16_79	63, MAGIC_F3
	SHA1_STEP_16_79	64, MAGIC_F3
	SHA1_STEP_16_79	65, MAGIC_F3
	SHA1_STEP_16_79	66, MAGIC_F3
	SHA1_STEP_16_79	67, MAGIC_F3
	SHA1_STEP_16_79	68, MAGIC_F3
	SHA1_STEP_16_79	69, MAGIC_F3
	SHA1_STEP_16_79	70, MAGIC_F3
	SHA1_STEP_16_79	71, MAGIC_F3
	SHA1_STEP_16_79	72, MAGIC_F3
	SHA1_STEP_16_79	73, MAGIC_F3
	SHA1_STEP_16_79	74, MAGIC_F3
	SHA1_STEP_16_79	75, MAGIC_F3
	SHA1_STEP_16_79	76, MAGIC_F3
	SHA1_STEP_16_79	77, MAGIC_F3
	SHA1_STEP_16_79	78, MAGIC_F3
	SHA1_STEP_16_79	79, MAGIC_F3

	# add old digest
	addw	WA, WA, AA
	addw	WB, WB, BB
	addw	WC, WC, CC
	addw	WD, WD, DD
	addw	WE, WE, EE

	addi	a1, a1, -1
	bnez	a1, .block_loop

	# write out digest
	sw	WA,  0(DGST)
	sw	WB,  4(DGST)
	sw	WC,  8(DGST)
	sw	WD, 12(DGST)
	sw	WE, 16(DGST)

	RESTORE_STACKS

.done:
	ret

	.size	sha1_riscv64_x1, .-sha1_riscv64_x1
