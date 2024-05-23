;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2017 Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; code to compute 16 SHA256 using AVX-512
;;

%include "reg_sizes.asm"

[bits 64]
default rel
section .text

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifidn __OUTPUT_FORMAT__, elf64
 ; Linux
 %define arg0  rdi
 %define arg1  rsi
 %define arg2  rdx
 %define arg3  rcx

 %define arg4  r8
 %define arg5  r9

 %define tmp1  r10
 %define tmp2  r11
 %define tmp3  r12		; must be saved and restored
 %define tmp4  r13		; must be saved and restored
 %define tmp5  r14		; must be saved and restored
 %define tmp6  r15		; must be saved and restored
 %define return rax

 %define func(x) x:
 %macro FUNC_SAVE 0
	push	r12
	push	r13
	push	r14
	push	r15
 %endmacro
 %macro FUNC_RESTORE 0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
 %endmacro
%else
 ; Windows
 %define arg0   rcx
 %define arg1   rdx
 %define arg2   r8
 %define arg3   r9

 %define arg4   r10
 %define arg5   r11
 %define tmp1   r12		; must be saved and restored
 %define tmp2   r13		; must be saved and restored
 %define tmp3   r14		; must be saved and restored
 %define tmp4   r15		; must be saved and restored
 %define tmp5   rdi		; must be saved and restored
 %define tmp6   rsi		; must be saved and restored
 %define return rax

 %define stack_size  10*16 + 7*8		; must be an odd multiple of 8
 %define func(x) proc_frame x
 %macro FUNC_SAVE 0
	alloc_stack	stack_size
	save_xmm128	xmm6, 0*16
	save_xmm128	xmm7, 1*16
	save_xmm128	xmm8, 2*16
	save_xmm128	xmm9, 3*16
	save_xmm128	xmm10, 4*16
	save_xmm128	xmm11, 5*16
	save_xmm128	xmm12, 6*16
	save_xmm128	xmm13, 7*16
	save_xmm128	xmm14, 8*16
	save_xmm128	xmm15, 9*16
	save_reg	r12,  10*16 + 0*8
	save_reg	r13,  10*16 + 1*8
	save_reg	r14,  10*16 + 2*8
	save_reg	r15,  10*16 + 3*8
	save_reg	rdi,  10*16 + 4*8
	save_reg	rsi,  10*16 + 5*8
	end_prolog
 %endmacro

 %macro FUNC_RESTORE 0
	movdqa	xmm6, [rsp + 0*16]
	movdqa	xmm7, [rsp + 1*16]
	movdqa	xmm8, [rsp + 2*16]
	movdqa	xmm9, [rsp + 3*16]
	movdqa	xmm10, [rsp + 4*16]
	movdqa	xmm11, [rsp + 5*16]
	movdqa	xmm12, [rsp + 6*16]
	movdqa	xmm13, [rsp + 7*16]
	movdqa	xmm14, [rsp + 8*16]
	movdqa	xmm15, [rsp + 9*16]
	mov	r12,  [rsp + 10*16 + 0*8]
	mov	r13,  [rsp + 10*16 + 1*8]
	mov	r14,  [rsp + 10*16 + 2*8]
	mov	r15,  [rsp + 10*16 + 3*8]
	mov	rdi,  [rsp + 10*16 + 4*8]
	mov	rsi,  [rsp + 10*16 + 5*8]
	add	rsp, stack_size
 %endmacro
%endif
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define loops 		arg3
;variables of mh_sha256
%define mh_in_p  	arg0
%define mh_digests_p 	arg1
%define mh_data_p	arg2
;variables used by storing segs_digests on stack
%define RSP_SAVE	tmp2
%define FRAMESZ 	4*8*16		;BYTES*DWORDS*SEGS
; Common definitions
%define ROUND	tmp4
%define TBL	tmp5

%define pref	tmp3
%macro PREFETCH_X 1
%define %%mem  %1
	prefetcht1  %%mem
%endmacro
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define VMOVPS  vmovups

%define A	zmm0
%define B	zmm1
%define C	zmm2
%define D	zmm3
%define E	zmm4
%define F	zmm5
%define G	zmm6
%define H	zmm7
%define T1	zmm8
%define TMP0	zmm9
%define TMP1	zmm10
%define TMP2	zmm11
%define TMP3	zmm12
%define TMP4	zmm13
%define TMP5	zmm14
%define TMP6	zmm15

%define W0	zmm16
%define W1	zmm17
%define W2	zmm18
%define W3	zmm19
%define W4	zmm20
%define W5	zmm21
%define W6	zmm22
%define W7	zmm23
%define W8	zmm24
%define W9	zmm25
%define W10	zmm26
%define W11	zmm27
%define W12	zmm28
%define W13	zmm29
%define W14	zmm30
%define W15	zmm31

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro ROTATE_ARGS 0
%xdefine TMP_ H
%xdefine H G
%xdefine G F
%xdefine F E
%xdefine E D
%xdefine D C
%xdefine C B
%xdefine B A
%xdefine A TMP_
%endm

%define APPEND(a,b) a %+ b
;;  CH(A, B, C) = (A&B) ^ (~A&C)
;; MAJ(E, F, G) = (E&F) ^ (E&G) ^ (F&G)
;; SIGMA0 = ROR_2  ^ ROR_13 ^ ROR_22
;; SIGMA1 = ROR_6  ^ ROR_11 ^ ROR_25
;; sigma0 = ROR_7  ^ ROR_18 ^ SHR_3
;; sigma1 = ROR_17 ^ ROR_19 ^ SHR_10

; Main processing loop per round
%macro PROCESS_LOOP 2
%define %%WT	%1
%define %%ROUND	%2
	;; T1 = H + SIGMA1(E) + CH(E, F, G) + Kt + Wt
	;; T2 = SIGMA0(A) + MAJ(A, B, C)
	;; H=G, G=F, F=E, E=D+T1, D=C, C=B, B=A, A=T1+T2

	;; H becomes T2, then add T1 for A
	;; D becomes D + T1 for E

	vpaddd		T1, H, [TBL + %%ROUND*4]{1to16}	; T1 = H + Kt
	vmovdqa32	TMP0, E
	vprord		TMP1, E, 6 		; ROR_6(E)
	vprord		TMP2, E, 11 		; ROR_11(E)
	vprord		TMP3, E, 25 		; ROR_25(E)
	vpternlogd	TMP0, F, G, 0xCA	; TMP0 = CH(E,F,G)
	vpaddd		T1, T1, %%WT		; T1 = T1 + Wt
	vpternlogd	TMP1, TMP2, TMP3, 0x96	; TMP1 = SIGMA1(E)
	vpaddd		T1, T1, TMP0		; T1 = T1 + CH(E,F,G)
	vpaddd		T1, T1, TMP1		; T1 = T1 + SIGMA1(E)
	vpaddd		D, D, T1		; D = D + T1

	vprord		H, A, 2 		; ROR_2(A)
	vprord		TMP2, A, 13 		; ROR_13(A)
	vprord		TMP3, A, 22 		; ROR_22(A)
	vmovdqa32	TMP0, A
	vpternlogd	TMP0, B, C, 0xE8	; TMP0 = MAJ(A,B,C)
	vpternlogd	H, TMP2, TMP3, 0x96	; H(T2) = SIGMA0(A)
	vpaddd		H, H, TMP0		; H(T2) = SIGMA0(A) + MAJ(A,B,C)
	vpaddd		H, H, T1		; H(A) = H(T2) + T1


	;; Rotate the args A-H (rotation of names associated with regs)
	ROTATE_ARGS
%endmacro

%macro MSG_SCHED_ROUND_16_63 4
%define %%WT	%1
%define %%WTp1	%2
%define %%WTp9	%3
%define %%WTp14	%4
	vprord		TMP4, %%WTp14, 17 	; ROR_17(Wt-2)
	vprord		TMP5, %%WTp14, 19 	; ROR_19(Wt-2)
	vpsrld		TMP6, %%WTp14, 10 	; SHR_10(Wt-2)
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma1(Wt-2)

	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2)
	vpaddd		%%WT, %%WT, %%WTp9	; Wt = Wt-16 + sigma1(Wt-2) + Wt-7

	vprord		TMP4, %%WTp1, 7 	; ROR_7(Wt-15)
	vprord		TMP5, %%WTp1, 18 	; ROR_18(Wt-15)
	vpsrld		TMP6, %%WTp1, 3 	; SHR_3(Wt-15)
	vpternlogd	TMP4, TMP5, TMP6, 0x96	; TMP4 = sigma0(Wt-15)

	vpaddd		%%WT, %%WT, TMP4	; Wt = Wt-16 + sigma1(Wt-2) +
						;      Wt-7 + sigma0(Wt-15) +
%endmacro

; Note this is reading in a block of data for one lane
; When all 16 are read, the data must be transposed to build msg schedule
%macro MSG_SCHED_ROUND_00_15 2
%define %%WT	 %1
%define %%OFFSET %2
	mov		inp0, [IN + (%%OFFSET*8)]
	vmovups		%%WT, [inp0+IDX]
%endmacro

;init hash digests
; segs_digests:low addr-> high_addr
; a  | b  |  c | ...|  p | (16)
; h0 | h0 | h0 | ...| h0 |    | Aa| Ab | Ac |...| Ap |
; h1 | h1 | h1 | ...| h1 |    | Ba| Bb | Bc |...| Bp |
; ....
; h7 | h7 | h7 | ...| h7 |    | Ha| Hb | Hc |...| Hp |

[bits 64]
section .text
align 32

;void _mh_sha256_block_avx512(const uint8_t * input_data, uint32_t digests[ISAL_SHA256_DIGEST_WORDS][ISAL_HASH_SEGS],
;		uint8_t frame_buffer[ISAL_MH_SHA256_BLOCK_SIZE], uint32_t num_blocks);
; arg 0 pointer to input data
; arg 1 pointer to digests, include segments digests(uint32_t digests[16][8])
; arg 2 pointer to aligned_frame_buffer which is used to save the big_endian data.
; arg 3 number  of 1KB blocks
;
mk_global _mh_sha256_block_avx512, function, internal
func(_mh_sha256_block_avx512)
	endbranch
	FUNC_SAVE
	; save rsp
	mov	RSP_SAVE, rsp

	test	loops, loops
	jle	.return

	; leave enough space to store segs_digests
	sub     rsp, FRAMESZ
	; align rsp to 64 Bytes needed by avx512
	and	rsp, ~0x3F
	lea	TBL,[TABLE]

	; copy segs_digests into stack and ZMM
	VMOVPS  A, [mh_digests_p + 64*0]
	VMOVPS  B, [mh_digests_p + 64*1]
	VMOVPS  C, [mh_digests_p + 64*2]
	VMOVPS  D, [mh_digests_p + 64*3]
	VMOVPS  E, [mh_digests_p + 64*4]
	VMOVPS  F, [mh_digests_p + 64*5]
	VMOVPS  G, [mh_digests_p + 64*6]
	VMOVPS  H, [mh_digests_p + 64*7]

.block_loop:
	; Save digests for later addition
	vmovdqa32 [rsp + 64*0], A
	vmovdqa32 [rsp + 64*1], B
	vmovdqa32 [rsp + 64*2], C
	vmovdqa32 [rsp + 64*3], D
	vmovdqa32 [rsp + 64*4], E
	vmovdqa32 [rsp + 64*5], F
	vmovdqa32 [rsp + 64*6], G
	vmovdqa32 [rsp + 64*7], H

	;transform to big-endian data and store on aligned_frame
	vbroadcasti32x4	TMP2, [PSHUFFLE_BYTE_FLIP_MASK]
	;using extra 16 ZMM registers instead of heap
%assign I 0
%rep 8
%assign J (I+1)
	VMOVPS	APPEND(W,I),[mh_in_p + I*64+0*64]
	VMOVPS	APPEND(W,J),[mh_in_p + I*64+1*64]

	vpshufb	APPEND(W,I), APPEND(W,I), TMP2
	vpshufb	APPEND(W,J), APPEND(W,J), TMP2
%assign I (I+2)
%endrep

	; MSG Schedule for W0-W15 is now complete in registers
	; Process first 48 rounds
	; Calculate next Wt+16 after processing is complete and Wt is unneeded

	; PROCESS_LOOP_00_47 APPEND(W,J), I, APPEND(W,K), APPEND(W,L), APPEND(W,M)

%assign I 0
%assign J 0
%assign K 1
%assign L 9
%assign M 14
%rep 64
	PROCESS_LOOP  APPEND(W,J),  I
	%if I < 48
	MSG_SCHED_ROUND_16_63  APPEND(W,J), APPEND(W,K), APPEND(W,L), APPEND(W,M)
	%endif
	%if I % 8 = 4
		PREFETCH_X [mh_in_p + 1024+128*(I / 8)]
	%endif
%assign I (I+1)
%assign J ((J+1)% 16)
%assign K ((K+1)% 16)
%assign L ((L+1)% 16)
%assign M ((M+1)% 16)
%endrep

	;; add old digest
	vpaddd	A, A, [rsp + 0*64]
	vpaddd	B, B, [rsp + 1*64]
	vpaddd	C, C, [rsp + 2*64]
	vpaddd	D, D, [rsp + 3*64]
	vpaddd	E, E, [rsp + 4*64]
	vpaddd	F, F, [rsp + 5*64]
	vpaddd	G, G, [rsp + 6*64]
	vpaddd	H, H, [rsp + 7*64]

	add 	mh_in_p,   1024
	sub     loops, 1
	jne     .block_loop

	; copy segs_digests back to mh_digests_p

	VMOVPS  [mh_digests_p + 64*0], A
	VMOVPS  [mh_digests_p + 64*1], B
	VMOVPS  [mh_digests_p + 64*2], C
	VMOVPS  [mh_digests_p + 64*3], D
	VMOVPS  [mh_digests_p + 64*4], E
	VMOVPS  [mh_digests_p + 64*5], F
	VMOVPS  [mh_digests_p + 64*6], G
	VMOVPS  [mh_digests_p + 64*7], H

	mov	rsp, RSP_SAVE			; restore rsp

.return:
	FUNC_RESTORE
	ret

endproc_frame

section .data
align 64
TABLE:
	dd	0x428a2f98
	dd	0x71374491
	dd	0xb5c0fbcf
	dd	0xe9b5dba5
	dd	0x3956c25b
	dd	0x59f111f1
	dd	0x923f82a4
	dd	0xab1c5ed5
	dd	0xd807aa98
	dd	0x12835b01
	dd	0x243185be
	dd	0x550c7dc3
	dd	0x72be5d74
	dd	0x80deb1fe
	dd	0x9bdc06a7
	dd	0xc19bf174
	dd	0xe49b69c1
	dd	0xefbe4786
	dd	0x0fc19dc6
	dd	0x240ca1cc
	dd	0x2de92c6f
	dd	0x4a7484aa
	dd	0x5cb0a9dc
	dd	0x76f988da
	dd	0x983e5152
	dd	0xa831c66d
	dd	0xb00327c8
	dd	0xbf597fc7
	dd	0xc6e00bf3
	dd	0xd5a79147
	dd	0x06ca6351
	dd	0x14292967
	dd	0x27b70a85
	dd	0x2e1b2138
	dd	0x4d2c6dfc
	dd	0x53380d13
	dd	0x650a7354
	dd	0x766a0abb
	dd	0x81c2c92e
	dd	0x92722c85
	dd	0xa2bfe8a1
	dd	0xa81a664b
	dd	0xc24b8b70
	dd	0xc76c51a3
	dd	0xd192e819
	dd	0xd6990624
	dd	0xf40e3585
	dd	0x106aa070
	dd	0x19a4c116
	dd	0x1e376c08
	dd	0x2748774c
	dd	0x34b0bcb5
	dd	0x391c0cb3
	dd	0x4ed8aa4a
	dd	0x5b9cca4f
	dd	0x682e6ff3
	dd	0x748f82ee
	dd	0x78a5636f
	dd	0x84c87814
	dd	0x8cc70208
	dd	0x90befffa
	dd	0xa4506ceb
	dd	0xbef9a3f7
	dd	0xc67178f2


PSHUFFLE_BYTE_FLIP_MASK: dq 0x0405060700010203, 0x0c0d0e0f08090a0b
