;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2016 Intel Corporation All rights reserved.
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

%include "sha256_mb_mgr_datastruct.asm"
%include "reg_sizes.asm"

%ifdef HAVE_AS_KNOWS_AVX512

[bits 64]
default rel
section .text

;; code to compute oct SHA256 using SSE-256 / AVX512
;; outer calling routine takes care of save and restore of XMM registers
;; Logic designed/laid out by JDG

;; Function clobbers: rax, rcx, rdx,   rbx, rsi, rdi, r9-r15; zmm0-31
;; Windows clobbers:  rax rbx     rdx rsi rdi        r9 r10 r11 r12 r13 r14 r15
;; Windows preserves:         rcx             rbp r8
;;
;; Linux clobbers:    rax rbx rcx rdx rsi            r9 r10 r11 r12 r13 r14 r15
;; Linux preserves:                       rdi rbp r8
;;
;; clobbers zmm0-31

%define APPEND(a,b) a %+ b

; Define Stack Layout
START_FIELDS
;;;     name            size    align
FIELD	_DIGEST_SAVE,	8*64,	64
FIELD	_rsp,		8,	8
%assign STACK_SPACE	_FIELD_OFFSET

%ifidn __OUTPUT_FORMAT__, win64
   %define arg1 rcx	; arg0 preserved
   %define arg2 rdx	; arg1
   %define reg3 r8	; arg2 preserved
   %define reg4 r9	; arg3
   %define var1 rdi
   %define var2 rsi
   %define local_func_decl(func_name) global func_name
 %else
   %define arg1 rdi	; arg0
   %define arg2 rsi	; arg1
   %define var1 rdx	; arg2
   %define var2 rcx	; arg3
   %define local_func_decl(func_name) mk_global func_name, function, internal
%endif

%define state    arg1
%define num_blks arg2

%define	IN	(state + _data_ptr)
%define DIGEST	state
%define SIZE	num_blks

%define IDX  var1
%define TBL  var2

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

%define inp0	r9
%define inp1	r10
%define inp2	r11
%define inp3	r12
%define inp4	r13
%define inp5	r14
%define inp6	r15
%define inp7	rax

%macro TRANSPOSE16 18
%define %%r0 %1
%define %%r1 %2
%define %%r2 %3
%define %%r3 %4
%define %%r4 %5
%define %%r5 %6
%define %%r6 %7
%define %%r7 %8
%define %%r8 %9
%define %%r9 %10
%define %%r10 %11
%define %%r11 %12
%define %%r12 %13
%define %%r13 %14
%define %%r14 %15
%define %%r15 %16
%define %%t0 %17
%define %%t1 %18

; r0  = {a15 a14 a13 a12   a11 a10 a9 a8   a7 a6 a5 a4   a3 a2 a1 a0}
; r1  = {b15 b14 b13 b12   b11 b10 b9 b8   b7 b6 b5 b4   b3 b2 b1 b0}
; r2  = {c15 c14 c13 c12   c11 c10 c9 c8   c7 c6 c5 c4   c3 c2 c1 c0}
; r3  = {d15 d14 d13 d12   d11 d10 d9 d8   d7 d6 d5 d4   d3 d2 d1 d0}
; r4  = {e15 e14 e13 e12   e11 e10 e9 e8   e7 e6 e5 e4   e3 e2 e1 e0}
; r5  = {f15 f14 f13 f12   f11 f10 f9 f8   f7 f6 f5 f4   f3 f2 f1 f0}
; r6  = {g15 g14 g13 g12   g11 g10 g9 g8   g7 g6 g5 g4   g3 g2 g1 g0}
; r7  = {h15 h14 h13 h12   h11 h10 h9 h8   h7 h6 h5 h4   h3 h2 h1 h0}
; r8  = {i15 i14 i13 i12   i11 i10 i9 i8   i7 i6 i5 i4   i3 i2 i1 i0}
; r9  = {j15 j14 j13 j12   j11 j10 j9 j8   j7 j6 j5 j4   j3 j2 j1 j0}
; r10 = {k15 k14 k13 k12   k11 k10 k9 k8   k7 k6 k5 k4   k3 k2 k1 k0}
; r11 = {l15 l14 l13 l12   l11 l10 l9 l8   l7 l6 l5 l4   l3 l2 l1 l0}
; r12 = {m15 m14 m13 m12   m11 m10 m9 m8   m7 m6 m5 m4   m3 m2 m1 m0}
; r13 = {n15 n14 n13 n12   n11 n10 n9 n8   n7 n6 n5 n4   n3 n2 n1 n0}
; r14 = {o15 o14 o13 o12   o11 o10 o9 o8   o7 o6 o5 o4   o3 o2 o1 o0}
; r15 = {p15 p14 p13 p12   p11 p10 p9 p8   p7 p6 p5 p4   p3 p2 p1 p0}

; r0   = {p0  o0  n0  m0    l0  k0  j0  i0    h0  g0  f0  e0    d0  c0  b0  a0}
; r1   = {p1  o1  n1  m1    l1  k1  j1  i1    h1  g1  f1  e1    d1  c1  b1  a1}
; r2   = {p2  o2  n2  m2    l2  k2  j2  i2    h2  g2  f2  e2    d2  c2  b2  a2}
; r3   = {p3  o3  n3  m3    l3  k3  j3  i3    h3  g3  f3  e3    d3  c3  b3  a3}
; r4   = {p4  o4  n4  m4    l4  k4  j4  i4    h4  g4  f4  e4    d4  c4  b4  a4}
; r5   = {p5  o5  n5  m5    l5  k5  j5  i5    h5  g5  f5  e5    d5  c5  b5  a5}
; r6   = {p6  o6  n6  m6    l6  k6  j6  i6    h6  g6  f6  e6    d6  c6  b6  a6}
; r7   = {p7  o7  n7  m7    l7  k7  j7  i7    h7  g7  f7  e7    d7  c7  b7  a7}
; r8   = {p8  o8  n8  m8    l8  k8  j8  i8    h8  g8  f8  e8    d8  c8  b8  a8}
; r9   = {p9  o9  n9  m9    l9  k9  j9  i9    h9  g9  f9  e9    d9  c9  b9  a9}
; r10  = {p10 o10 n10 m10   l10 k10 j10 i10   h10 g10 f10 e10   d10 c10 b10 a10}
; r11  = {p11 o11 n11 m11   l11 k11 j11 i11   h11 g11 f11 e11   d11 c11 b11 a11}
; r12  = {p12 o12 n12 m12   l12 k12 j12 i12   h12 g12 f12 e12   d12 c12 b12 a12}
; r13  = {p13 o13 n13 m13   l13 k13 j13 i13   h13 g13 f13 e13   d13 c13 b13 a13}
; r14  = {p14 o14 n14 m14   l14 k14 j14 i14   h14 g14 f14 e14   d14 c14 b14 a14}
; r15  = {p15 o15 n15 m15   l15 k15 j15 i15   h15 g15 f15 e15   d15 c15 b15 a15}


	; process top half (r0..r3) {a...d}
	vshufps	%%t0, %%r0, %%r1, 0x44	; t0 = {b13 b12 a13 a12   b9  b8  a9  a8   b5 b4 a5 a4   b1 b0 a1 a0}
	vshufps	%%r0, %%r0, %%r1, 0xEE	; r0 = {b15 b14 a15 a14   b11 b10 a11 a10  b7 b6 a7 a6   b3 b2 a3 a2}
	vshufps	%%t1, %%r2, %%r3, 0x44	; t1 = {d13 d12 c13 c12   d9  d8  c9  c8   d5 d4 c5 c4   d1 d0 c1 c0}
	vshufps	%%r2, %%r2, %%r3, 0xEE	; r2 = {d15 d14 c15 c14   d11 d10 c11 c10  d7 d6 c7 c6   d3 d2 c3 c2}

	vshufps	%%r3, %%t0, %%t1, 0xDD	; r3 = {d13 c13 b13 a13   d9  c9  b9  a9   d5 c5 b5 a5   d1 c1 b1 a1}
	vshufps	%%r1, %%r0, %%r2, 0x88	; r1 = {d14 c14 b14 a14   d10 c10 b10 a10  d6 c6 b6 a6   d2 c2 b2 a2}
	vshufps	%%r0, %%r0, %%r2, 0xDD	; r0 = {d15 c15 b15 a15   d11 c11 b11 a11  d7 c7 b7 a7   d3 c3 b3 a3}
	vshufps	%%t0, %%t0, %%t1, 0x88	; t0 = {d12 c12 b12 a12   d8  c8  b8  a8   d4 c4 b4 a4   d0 c0 b0 a0}

	; use r2 in place of t0
	vshufps	%%r2, %%r4, %%r5, 0x44	; r2 = {f13 f12 e13 e12   f9  f8  e9  e8   f5 f4 e5 e4   f1 f0 e1 e0}
	vshufps	%%r4, %%r4, %%r5, 0xEE	; r4 = {f15 f14 e15 e14   f11 f10 e11 e10  f7 f6 e7 e6   f3 f2 e3 e2}
	vshufps %%t1, %%r6, %%r7, 0x44	; t1 = {h13 h12 g13 g12   h9  h8  g9  g8   h5 h4 g5 g4   h1 h0 g1 g0}
	vshufps	%%r6, %%r6, %%r7, 0xEE	; r6 = {h15 h14 g15 g14   h11 h10 g11 g10  h7 h6 g7 g6   h3 h2 g3 g2}

	vshufps	%%r7, %%r2, %%t1, 0xDD	; r7 = {h13 g13 f13 e13   h9  g9  f9  e9   h5 g5 f5 e5   h1 g1 f1 e1}
	vshufps	%%r5, %%r4, %%r6, 0x88	; r5 = {h14 g14 f14 e14   h10 g10 f10 e10  h6 g6 f6 e6   h2 g2 f2 e2}
	vshufps	%%r4, %%r4, %%r6, 0xDD	; r4 = {h15 g15 f15 e15   h11 g11 f11 e11  h7 g7 f7 e7   h3 g3 f3 e3}
	vshufps	%%r2, %%r2, %%t1, 0x88	; r2 = {h12 g12 f12 e12   h8  g8  f8  e8   h4 g4 f4 e4   h0 g0 f0 e0}

	; use r6 in place of t0
	vshufps	%%r6, %%r8, %%r9,    0x44	; r6  = {j13 j12 i13 i12   j9  j8  i9  i8   j5 j4 i5 i4   j1 j0 i1 i0}
	vshufps	%%r8, %%r8, %%r9,    0xEE	; r8  = {j15 j14 i15 i14   j11 j10 i11 i10  j7 j6 i7 i6   j3 j2 i3 i2}
	vshufps	%%t1, %%r10, %%r11,  0x44	; t1  = {l13 l12 k13 k12   l9  l8  k9  k8   l5 l4 k5 k4   l1 l0 k1 k0}
	vshufps	%%r10, %%r10, %%r11, 0xEE	; r10 = {l15 l14 k15 k14   l11 l10 k11 k10  l7 l6 k7 k6   l3 l2 k3 k2}

	vshufps	%%r11, %%r6, %%t1, 0xDD		; r11 = {l13 k13 j13 113   l9  k9  j9  i9   l5 k5 j5 i5   l1 k1 j1 i1}
	vshufps	%%r9, %%r8, %%r10, 0x88		; r9  = {l14 k14 j14 114   l10 k10 j10 i10  l6 k6 j6 i6   l2 k2 j2 i2}
	vshufps	%%r8, %%r8, %%r10, 0xDD		; r8  = {l15 k15 j15 115   l11 k11 j11 i11  l7 k7 j7 i7   l3 k3 j3 i3}
	vshufps	%%r6, %%r6, %%t1,  0x88		; r6  = {l12 k12 j12 112   l8  k8  j8  i8   l4 k4 j4 i4   l0 k0 j0 i0}

	; use r10 in place of t0
	vshufps	%%r10, %%r12, %%r13, 0x44	; r10 = {n13 n12 m13 m12   n9  n8  m9  m8   n5 n4 m5 m4   n1 n0 a1 m0}
	vshufps	%%r12, %%r12, %%r13, 0xEE	; r12 = {n15 n14 m15 m14   n11 n10 m11 m10  n7 n6 m7 m6   n3 n2 a3 m2}
	vshufps	%%t1, %%r14, %%r15,  0x44	; t1  = {p13 p12 013 012   p9  p8  09  08   p5 p4 05 04   p1 p0 01 00}
	vshufps	%%r14, %%r14, %%r15, 0xEE	; r14 = {p15 p14 015 014   p11 p10 011 010  p7 p6 07 06   p3 p2 03 02}

	vshufps	%%r15, %%r10, %%t1,  0xDD	; r15 = {p13 013 n13 m13   p9  09  n9  m9   p5 05 n5 m5   p1 01 n1 m1}
	vshufps	%%r13, %%r12, %%r14, 0x88	; r13 = {p14 014 n14 m14   p10 010 n10 m10  p6 06 n6 m6   p2 02 n2 m2}
	vshufps	%%r12, %%r12, %%r14, 0xDD	; r12 = {p15 015 n15 m15   p11 011 n11 m11  p7 07 n7 m7   p3 03 n3 m3}
	vshufps	%%r10, %%r10, %%t1,  0x88	; r10 = {p12 012 n12 m12   p8  08  n8  m8   p4 04 n4 m4   p0 00 n0 m0}

;; At this point, the registers that contain interesting data are:
;; t0, r3, r1, r0, r2, r7, r5, r4, r6, r11, r9, r8, r10, r15, r13, r12
;; Can use t1 and r14 as scratch registers

	vmovdqa32 %%r14, TMP5
	vpermi2q  %%r14, %%t0, %%r2		; r14 = {h8  g8  f8  e8   d8  c8  b8  a8   h0 g0 f0 e0	 d0 c0 b0 a0}
	vmovdqa32 %%t1,  TMP6
	vpermi2q  %%t1,  %%t0, %%r2		; t1  = {h12 g12 f12 e12  d12 c12 b12 a12  h4 g4 f4 e4	 d4 c4 b4 a4}

	vmovdqa32 %%r2, TMP5
	vpermi2q  %%r2, %%r3, %%r7		; r2  = {h9  g9  f9  e9   d9  c9  b9  a9   h1 g1 f1 e1	 d1 c1 b1 a1}
	vmovdqa32 %%t0, TMP6
	vpermi2q  %%t0, %%r3, %%r7		; t0  = {h13 g13 f13 e13  d13 c13 b13 a13  h5 g5 f5 e5	 d5 c5 b5 a5}

	vmovdqa32 %%r3, TMP5
	vpermi2q  %%r3, %%r1, %%r5		; r3  = {h10 g10 f10 e10  d10 c10 b10 a10  h2 g2 f2 e2	 d2 c2 b2 a2}
	vmovdqa32 %%r7, TMP6
	vpermi2q  %%r7, %%r1, %%r5		; r7  = {h14 g14 f14 e14  d14 c14 b14 a14  h6 g6 f6 e6	 d6 c6 b6 a6}

	vmovdqa32 %%r1, TMP5
	vpermi2q  %%r1, %%r0, %%r4		; r1  = {h11 g11 f11 e11  d11 c11 b11 a11  h3 g3 f3 e3	 d3 c3 b3 a3}
	vmovdqa32 %%r5, TMP6
	vpermi2q  %%r5, %%r0, %%r4		; r5  = {h15 g15 f15 e15  d15 c15 b15 a15  h7 g7 f7 e7	 d7 c7 b7 a7}

	vmovdqa32 %%r0, TMP5
	vpermi2q  %%r0, %%r6, %%r10		; r0 = {p8  o8  n8  m8   l8  k8  j8  i8   p0 o0 n0 m0	 l0 k0 j0 i0}
	vmovdqa32 %%r4,  TMP6
	vpermi2q  %%r4, %%r6, %%r10		; r4  = {p12 o12 n12 m12  l12 k12 j12 i12  p4 o4 n4 m4	 l4 k4 j4 i4}

	vmovdqa32 %%r6, TMP5
	vpermi2q  %%r6, %%r11, %%r15		; r6  = {p9  o9  n9  m9   l9  k9  j9  i9   p1 o1 n1 m1	 l1 k1 j1 i1}
	vmovdqa32 %%r10, TMP6
	vpermi2q  %%r10, %%r11, %%r15		; r10 = {p13 o13 n13 m13  l13 k13 j13 i13  p5 o5 n5 m5	 l5 k5 j5 i5}

	vmovdqa32 %%r11, TMP5
	vpermi2q  %%r11, %%r9, %%r13		; r11 = {p10 o10 n10 m10  l10 k10 j10 i10  p2 o2 n2 m2	 l2 k2 j2 i2}
	vmovdqa32 %%r15, TMP6
	vpermi2q  %%r15, %%r9, %%r13		; r15 = {p14 o14 n14 m14  l14 k14 j14 i14  p6 o6 n6 m6	 l6 k6 j6 i6}

	vmovdqa32 %%r9, TMP5
	vpermi2q  %%r9, %%r8, %%r12		; r9  = {p11 o11 n11 m11  l11 k11 j11 i11  p3 o3 n3 m3	 l3 k3 j3 i3}
	vmovdqa32 %%r13, TMP6
	vpermi2q  %%r13, %%r8, %%r12		; r13 = {p15 o15 n15 m15  l15 k15 j15 i15  p7 o7 n7 m7	 l7 k7 j7 i7}

;; At this point r8 and r12 can be used as scratch registers

	vshuff64x2 %%r8, %%r14, %%r0, 0xEE 	; r8  = {p8  o8  n8  m8   l8  k8  j8  i8   h8 g8 f8 e8   d8 c8 b8 a8}
	vshuff64x2 %%r0, %%r14, %%r0, 0x44 	; r0  = {p0  o0  n0  m0   l0  k0  j0  i0   h0 g0 f0 e0   d0 c0 b0 a0}

	vshuff64x2 %%r12, %%t1, %%r4, 0xEE 	; r12 = {p12 o12 n12 m12  l12 k12 j12 i12  h12 g12 f12 e12  d12 c12 b12 a12}
	vshuff64x2 %%r4, %%t1, %%r4, 0x44 	; r4  = {p4  o4  n4  m4   l4  k4  j4  i4   h4 g4 f4 e4   d4 c4 b4 a4}

	vshuff64x2 %%r14, %%r7, %%r15, 0xEE 	; r14 = {p14 o14 n14 m14  l14 k14 j14 i14  h14 g14 f14 e14  d14 c14 b14 a14}
	vshuff64x2 %%t1, %%r7, %%r15, 0x44 	; t1  = {p6  o6  n6  m6   l6  k6  j6  i6   h6 g6 f6 e6   d6 c6 b6 a6}

	vshuff64x2 %%r15, %%r5, %%r13, 0xEE 	; r15 = {p15 o15 n15 m15  l15 k15 j15 i15  h15 g15 f15 e15  d15 c15 b15 a15}
	vshuff64x2 %%r7, %%r5, %%r13, 0x44 	; r7  = {p7  o7  n7  m7   l7  k7  j7  i7   h7 g7 f7 e7   d7 c7 b7 a7}

	vshuff64x2 %%r13, %%t0, %%r10, 0xEE 	; r13 = {p13 o13 n13 m13  l13 k13 j13 i13  h13 g13 f13 e13  d13 c13 b13 a13}
	vshuff64x2 %%r5, %%t0, %%r10, 0x44 	; r5  = {p5  o5  n5  m5   l5  k5  j5  i5   h5 g5 f5 e5   d5 c5 b5 a5}

	vshuff64x2 %%r10, %%r3, %%r11, 0xEE 	; r10 = {p10 o10 n10 m10  l10 k10 j10 i10  h10 g10 f10 e10  d10 c10 b10 a10}
	vshuff64x2 %%t0, %%r3, %%r11, 0x44 	; t0  = {p2  o2  n2  m2   l2  k2  j2  i2   h2 g2 f2 e2   d2 c2 b2 a2}

	vshuff64x2 %%r11, %%r1, %%r9, 0xEE 	; r11 = {p11 o11 n11 m11  l11 k11 j11 i11  h11 g11 f11 e11  d11 c11 b11 a11}
	vshuff64x2 %%r3, %%r1, %%r9, 0x44 	; r3  = {p3  o3  n3  m3   l3  k3  j3  i3   h3 g3 f3 e3   d3 c3 b3 a3}

	vshuff64x2 %%r9, %%r2, %%r6, 0xEE 	; r9  = {p9  o9  n9  m9   l9  k9  j9  i9   h9 g9 f9 e9   d9 c9 b9 a9}
	vshuff64x2 %%r1, %%r2, %%r6, 0x44 	; r1  = {p1  o1  n1  m1   l1  k1  j1  i1   h1 g1 f1 e1   d1 c1 b1 a1}

	vmovdqa32 %%r2, %%t0			; r2  = {p2  o2  n2  m2   l2  k2  j2  i2   h2 g2 f2 e2   d2 c2 b2 a2}
	vmovdqa32 %%r6, %%t1			; r6  = {p6  o6  n6  m6   l6  k6  j6  i6   h6 g6 f6 e6   d6 c6 b6 a6}

%endmacro

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

	vpaddd		T1, H, [TBL + ((%%ROUND)*4)]{1to16}	; T1 = H + Kt
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

; This is supposed to be SKL optimized assuming:
; vpternlog, vpaddd ports 5,8
; vprord ports 1,8
; However, vprord is only working on port 8
;
; Main processing loop per round
; Get the msg schedule word 16 from the current, now unneccessary word
%macro PROCESS_LOOP_00_47 5
%define %%WT	%1
%define %%ROUND	%2
%define %%WTp1	%3
%define %%WTp9	%4
%define %%WTp14	%5
	;; T1 = H + SIGMA1(E) + CH(E, F, G) + Kt + Wt
	;; T2 = SIGMA0(A) + MAJ(A, B, C)
	;; H=G, G=F, F=E, E=D+T1, D=C, C=B, B=A, A=T1+T2

	;; H becomes T2, then add T1 for A
	;; D becomes D + T1 for E

	;; For next value in msg schedule
	;; Wt+16 = sigma1(Wt+14) + Wt+9 + sigma0(Wt+1) + Wt

	vmovdqa32	TMP0, E
	vprord		TMP1, E, 6 		; ROR_6(E)
	vprord		TMP2, E, 11 		; ROR_11(E)
	vprord		TMP3, E, 25 		; ROR_25(E)
	vpternlogd	TMP0, F, G, 0xCA	; TMP0 = CH(E,F,G)
	vpaddd		T1, H, %%WT		; T1 = H + Wt
	vpternlogd	TMP1, TMP2, TMP3, 0x96	; TMP1 = SIGMA1(E)
	vpaddd		T1, T1, [TBL + ((%%ROUND)*4)] {1to16}		; T1 = T1 + Kt
	vprord		H, A, 2 		; ROR_2(A)
	vpaddd		T1, T1, TMP0		; T1 = T1 + CH(E,F,G)
	vprord		TMP2, A, 13 		; ROR_13(A)
	vmovdqa32	TMP0, A
	vprord		TMP3, A, 22 		; ROR_22(A)
	vpaddd		T1, T1, TMP1		; T1 = T1 + SIGMA1(E)
	vpternlogd	TMP0, B, C, 0xE8	; TMP0 = MAJ(A,B,C)
	vpaddd		D, D, T1		; D = D + T1
	vpternlogd	H, TMP2, TMP3, 0x96	; H(T2) = SIGMA0(A)
	vpaddd		H, H, TMP0		; H(T2) = SIGMA0(A) + MAJ(A,B,C)
	vprord		TMP0, %%WTp14, 17 	; ROR_17(Wt-2)
	vprord		TMP1, %%WTp14, 19 	; ROR_19(Wt-2)
	vpsrld		TMP2, %%WTp14, 10 	; SHR_10(Wt-2)
	vpaddd		H, H, T1		; H(A) = H(T2) + T1
	vpternlogd	TMP0, TMP1, TMP2, 0x96	; TMP0 = sigma1(Wt-2)
	vpaddd		%%WT, %%WT, TMP0	; Wt = Wt-16 + sigma1(Wt-2)
	vprord		TMP0, %%WTp1, 7 	; ROR_7(Wt-15)
	vprord		TMP1, %%WTp1, 18 	; ROR_18(Wt-15)
	vpaddd		%%WT, %%WT, %%WTp9	; Wt = Wt-16 + sigma1(Wt-2) + Wt-7
	vpsrld		TMP2, %%WTp1, 3 	; SHR_3(Wt-15)
	vpternlogd	TMP0, TMP1, TMP2, 0x96	; TMP0 = sigma0(Wt-15)
	vpaddd		%%WT, %%WT, TMP0	; Wt = Wt-16 + sigma1(Wt-2) +
						;      Wt-7 + sigma0(Wt-15) +


	;; Rotate the args A-H (rotation of names associated with regs)
	ROTATE_ARGS
%endmacro

%macro MSG_SCHED_ROUND_16_63 4
%define %%WT	%1
%define %%WTp1	%2
%define %%WTp9	%3
%define %%WTp14	%4
	vprord		TMP0, %%WTp14, 17 	; ROR_17(Wt-2)
	vprord		TMP1, %%WTp14, 19 	; ROR_19(Wt-2)
	vpsrld		TMP2, %%WTp14, 10 	; SHR_10(Wt-2)
	vpternlogd	TMP0, TMP1, TMP2, 0x96	; TMP0 = sigma1(Wt-2)

	vpaddd		%%WT, %%WT, TMP0	; Wt = Wt-16 + sigma1(Wt-2)
	vpaddd		%%WT, %%WT, %%WTp9	; Wt = Wt-16 + sigma1(Wt-2) + Wt-7

	vprord		TMP0, %%WTp1, 7 	; ROR_7(Wt-15)
	vprord		TMP1, %%WTp1, 18 	; ROR_18(Wt-15)
	vpsrld		TMP2, %%WTp1, 3 	; SHR_3(Wt-15)
	vpternlogd	TMP0, TMP1, TMP2, 0x96	; TMP0 = sigma0(Wt-15)

	vpaddd		%%WT, %%WT, TMP0	; Wt = Wt-16 + sigma1(Wt-2) +
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

align 64

;; void sha256_mb_x16_avx512(SHA256_MB_ARGS_X16, uint32_t size)
; arg 1 : pointer to input data
; arg 2 : size (in blocks) ;; assumed to be >= 1
local_func_decl(sha256_mb_x16_avx512)
sha256_mb_x16_avx512:
	endbranch
	mov	rax, rsp
        sub     rsp, STACK_SPACE
	and	rsp, ~63	; align stack to multiple of 64
	mov	[rsp + _rsp], rax
	lea	TBL, [TABLE]

	;; Initialize digests
	vmovups	A, [DIGEST + 0*64]
	vmovups	B, [DIGEST + 1*64]
	vmovups	C, [DIGEST + 2*64]
	vmovups	D, [DIGEST + 3*64]
	vmovups	E, [DIGEST + 4*64]
	vmovups	F, [DIGEST + 5*64]
	vmovups	G, [DIGEST + 6*64]
	vmovups	H, [DIGEST + 7*64]

	; Do we need to transpose digests???
	; SHA1 does not, but SHA256 has been


	;; Read in first block of input data
	;; Transpose input data
	lea	IDX,  [IN]
	mov	inp0, [IDX + 0*8]
	mov	inp1, [IDX + 1*8]
	mov	inp2, [IDX + 2*8]
	mov	inp3, [IDX + 3*8]
	mov	inp4, [IDX + 4*8]
	mov	inp5, [IDX + 5*8]
	mov	inp6, [IDX + 6*8]
	mov	inp7, [IDX + 7*8]

	vmovups	W0,[inp0]
	vmovups	W1,[inp1]
	vmovups	W2,[inp2]
	vmovups	W3,[inp3]
	vmovups	W4,[inp4]
	vmovups	W5,[inp5]
	vmovups	W6,[inp6]
	vmovups	W7,[inp7]

	mov	inp0, [IDX + 8*8]
	mov	inp1, [IDX + 9*8]
	mov	inp2, [IDX +10*8]
	mov	inp3, [IDX +11*8]
	mov	inp4, [IDX +12*8]
	mov	inp5, [IDX +13*8]
	mov	inp6, [IDX +14*8]
	mov	inp7, [IDX +15*8]

	vmovups	W8, [inp0]
	vmovups	W9, [inp1]
	vmovups	W10,[inp2]
	vmovups	W11,[inp3]
	vmovups	W12,[inp4]
	vmovups	W13,[inp5]
	vmovups	W14,[inp6]
	vmovups	W15,[inp7]
	lea	IDX, [PSHUFFLE_BYTE_FLIP_MASK]
	vbroadcasti32x4 TMP4, [IDX]   ; PSHUFFLE_BYTE_FLIP_MASK
	vpmovzxbq	TMP5, [IDX+16]; PSHUFFLE_TRANSPOSE16_MASK1
	vpmovzxbq	TMP6, [IDX+16+8]; PSHUFFLE_TRANSPOSE16_MASK2
	xor IDX, IDX


align 32
lloop:


	; Save digests for later addition
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*0], A
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*1], B
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*2], C
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*3], D
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*4], E
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*5], F
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*6], G
        vmovdqa32	[rsp + _DIGEST_SAVE + 64*7], H

	add	IDX, 64

	TRANSPOSE16 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, TMP0, TMP1

%assign I 0
%rep 16
       	vpshufb	APPEND(W,I), APPEND(W,I), TMP4
%assign I (I+1)
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
%rep 48
	PROCESS_LOOP  APPEND(W,J),  I
	MSG_SCHED_ROUND_16_63  APPEND(W,J), APPEND(W,K), APPEND(W,L), APPEND(W,M)
%assign I (I+1)
%assign J ((J+1)% 16)
%assign K ((K+1)% 16)
%assign L ((L+1)% 16)
%assign M ((M+1)% 16)
%endrep

	; Check is this is the last block
	sub 	SIZE, 1
	je	lastLoop

	; Process last 16 rounds
	; Read in next block msg data for use in first 16 words of msg sched
%assign I 48
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J), I
	MSG_SCHED_ROUND_00_15  APPEND(W,J), J
%assign I (I+1)
%assign J (J+1)
%endrep

	; Add old digest
        vpaddd		A, A, [rsp + _DIGEST_SAVE + 64*0]
        vpaddd		B, B, [rsp + _DIGEST_SAVE + 64*1]
        vpaddd		C, C, [rsp + _DIGEST_SAVE + 64*2]
        vpaddd		D, D, [rsp + _DIGEST_SAVE + 64*3]
        vpaddd		E, E, [rsp + _DIGEST_SAVE + 64*4]
        vpaddd		F, F, [rsp + _DIGEST_SAVE + 64*5]
        vpaddd		G, G, [rsp + _DIGEST_SAVE + 64*6]
        vpaddd		H, H, [rsp + _DIGEST_SAVE + 64*7]

	jmp	lloop

align 16
lastLoop:
	; Process last 16 rounds
%assign I 48
%assign J 0
%rep 16
	PROCESS_LOOP  APPEND(W,J), I
%assign I (I+1)
%assign J (J+1)
%endrep

	; Add old digest
        vpaddd		A, A, [rsp + _DIGEST_SAVE + 64*0]
        vpaddd		B, B, [rsp + _DIGEST_SAVE + 64*1]
        vpaddd		C, C, [rsp + _DIGEST_SAVE + 64*2]
        vpaddd		D, D, [rsp + _DIGEST_SAVE + 64*3]
        vpaddd		E, E, [rsp + _DIGEST_SAVE + 64*4]
        vpaddd		F, F, [rsp + _DIGEST_SAVE + 64*5]
        vpaddd		G, G, [rsp + _DIGEST_SAVE + 64*6]
        vpaddd		H, H, [rsp + _DIGEST_SAVE + 64*7]

        ;; update into data pointers
	vpbroadcastq TMP1, IDX
	vpaddq	TMP0, TMP1, [IN]
	vpaddq	TMP1, TMP1, [IN+64]
	vmovdqu32 [IN], TMP0
	vmovdqu32  [IN+64], TMP1

	; Write out digest
	; Do we need to untranspose digests???
	vmovups	[DIGEST + 0*64], A
	vmovups	[DIGEST + 1*64], B
	vmovups	[DIGEST + 2*64], C
	vmovups	[DIGEST + 3*64], D
	vmovups	[DIGEST + 4*64], E
	vmovups	[DIGEST + 5*64], F
	vmovups	[DIGEST + 6*64], G
	vmovups	[DIGEST + 7*64], H


        mov     rsp, [rsp + _rsp]
        ret

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

PSHUFFLE_TRANSPOSE16_MASK1: 	db 0x0000000000000000
				db 0x0000000000000001
				db 0x0000000000000008
				db 0x0000000000000009
				db 0x0000000000000004
				db 0x0000000000000005
				db 0x000000000000000C
				db 0x000000000000000D

PSHUFFLE_TRANSPOSE16_MASK2: 	db 0x0000000000000002
				db 0x0000000000000003
				db 0x000000000000000A
				db 0x000000000000000B
				db 0x0000000000000006
				db 0x0000000000000007
				db 0x000000000000000E
				db 0x000000000000000F

%else
%ifidn __OUTPUT_FORMAT__, win64
global no_sha256_mb_x16_avx512
no_sha256_mb_x16_avx512:
%endif
%endif ; HAVE_AS_KNOWS_AVX512
