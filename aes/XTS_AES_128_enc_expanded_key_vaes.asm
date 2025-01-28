;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2020 Intel Corporation All rights reserved.
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
; XTS encrypt function with 128-bit AES
; expanded keys are not aligned
; keys are expanded in parallel with the tweak encryption
; plaintext and ciphertext are not aligned
; second key is stored in the stack as aligned to 16 Bytes
; first key is required only once, no need for storage of this key

%include "reg_sizes.asm"
%include "clear_regs.inc"

default rel

%ifidn __OUTPUT_FORMAT__, elf64
%define _gpr    rsp     ; store rbx
%define VARIABLE_OFFSET 8*1     ; stack frame size for rbx
%else
%define _xmm    rsp             ; store xmm6:xmm15
%define _gpr    rsp + 16*10     ; store rdi, rsi, rbx
%define VARIABLE_OFFSET 16*10 + 8*3     ; stack frame size for XMM6-15 and GP regs
%endif

%ifndef NROUNDS
%define NROUNDS 9
%define FUNC _XTS_AES_128_enc_expanded_key_vaes
%endif

%define GHASH_POLY 0x87

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void _XTS_AES_128_enc_expanded_key_vaes(
;               UINT8 *k2,      // key used for tweaking, 16*11 bytes
;               UINT8 *k1,      // key used for "ECB" encryption, 16*11 bytes
;               UINT8 *TW_initial,      // initial tweak value, 16 bytes
;               UINT64 N,       // sector size, in bytes
;               const UINT8 *pt,        // plaintext sector input data
;               UINT8 *ct);     // ciphertext sector output data
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; arguments for input parameters
%ifidn __OUTPUT_FORMAT__, elf64
	%xdefine ptr_key2 rdi
	%xdefine ptr_key1 rsi
	%xdefine T_val rdx
	%xdefine N_val rcx
	%xdefine ptr_plaintext r8
	%xdefine ptr_ciphertext r9
%else
	%xdefine ptr_key2 rcx
	%xdefine ptr_key1 rdx
	%xdefine T_val r8
	%xdefine N_val r9
	%xdefine ptr_plaintext r10
	%xdefine ptr_ciphertext r11
%endif

; arguments for temp parameters
%ifidn __OUTPUT_FORMAT__, elf64
	%define tmp1                    rdi
	%define ghash_poly_8b           r10
	%define ghash_poly_8b_temp      r11
%else
	%define tmp1                    rcx
	%define ghash_poly_8b           rdi
	%define ghash_poly_8b_temp      rsi
%endif

%define twtempl rax     ; global temp registers used for tweak computation
%define twtemph rbx
%define zpoly   zmm25
%define prev_tweak zmm31


; macro to encrypt the tweak value

%macro  encrypt_T 2
%define %%xstate_tweak  %1
%define %%ptr_key2      %2

	vpxorq   %%xstate_tweak, [%%ptr_key2]                    ; ARK for tweak encryption

        ; Do N AES rounds for tweak encryption
%assign %%I 1
%rep NROUNDS
	vaesenc  %%xstate_tweak, [%%ptr_key2 + 16*%%I]           ; round 1 for tweak encryption
%assign %%I (%%I + 1)
%endrep

	vaesenclast      %%xstate_tweak, [%%ptr_key2 + 16*(NROUNDS + 1)]    ; round 10 for tweak encryption
%endmacro


; encrypt final blocks of AES
; 1, 2, 3, 4, 5, 6 or 7 blocks are encrypted
; next 8 Tweak values are generated
%macro  encrypt_final 17
%define %%ST1   %1      ; state 1
%define %%ST2   %2      ; state 2
%define %%ST3   %3      ; state 3
%define %%ST4   %4      ; state 4
%define %%ST5   %5      ; state 5
%define %%ST6   %6      ; state 6
%define %%ST7   %7      ; state 7
%define %%ST8   %8      ; state 8

%define %%TW1   %9      ; tweak 1
%define %%TW2   %10     ; tweak 2
%define %%TW3   %11     ; tweak 3
%define %%TW4   %12     ; tweak 4
%define %%TW5   %13     ; tweak 5
%define %%TW6   %14     ; tweak 6
%define %%TW7   %15     ; tweak 7
%define %%T0    %16     ; Temp register
%define %%num_blocks    %17
; %%num_blocks blocks encrypted
; %%num_blocks can be 1, 2, 3, 4, 5, 6, 7

	; xor Tweak value + ARK
	vmovdqu  %%T0, [ptr_key1]
%assign %%I 1
%rep %%num_blocks
	vpternlogq %%ST %+ %%I, %%TW %+ %%I, %%T0, 0x96
%assign %%I (%%I + 1)
%endrep

	; AES rounds
%assign %%ROUND 1
%rep (NROUNDS + 1)
	vmovdqu  %%T0, [ptr_key1 + 16*%%ROUND]
%assign %%IDX 1
%rep %%num_blocks
%if %%ROUND == (NROUNDS + 1)
	vaesenclast  %%ST %+ %%IDX, %%T0
%else
	vaesenc  %%ST %+ %%IDX, %%T0
%endif
%assign %%IDX (%%IDX + 1)
%endrep

%assign %%ROUND (%%ROUND + 1)
%endrep

	; xor Tweak values
%assign %%I 1
%rep %%num_blocks
	vpxor   %%ST %+ %%I, %%TW %+ %%I
%assign %%I (%%I + 1)
%endrep

%endmacro

; Encrypt 4 blocks in parallel
%macro  encrypt_by_four_zmm 3
%define %%ST1   %1      ; state 1
%define %%TW1   %2      ; tweak 1
%define %%T0    %3     ; Temp register

	; xor Tweak values + ARK
	vbroadcasti32x4 %%T0, [ptr_key1]
	vpternlogq    %%ST1, %%TW1, %%T0, 0x96

	; AES rounds
%assign %%ROUND 1
%rep (NROUNDS + 1)
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
%if %%ROUND == (NROUNDS + 1)
	vaesenclast  %%ST1, %%T0
%else
	vaesenc  %%ST1, %%T0
%endif
%assign %%ROUND (%%ROUND + 1)
%endrep

	; xor Tweak values
	vpxorq    %%ST1, %%TW1

%endmacro


; Encrypt 8 blocks in parallel
; generate next 8 tweak values
%macro  encrypt_by_eight_zmm 6
%define %%ST1   %1      ; state 1
%define %%ST2   %2      ; state 2
%define %%TW1   %3      ; tweak 1
%define %%TW2   %4      ; tweak 2
%define %%T0    %5     ; Temp register
%define %%last_eight     %6

	; xor Tweak values + ARK
	vbroadcasti32x4 %%T0, [ptr_key1]
	vpternlogq    %%ST1, %%TW1, %%T0, 0x96
	vpternlogq    %%ST2, %%TW2, %%T0, 0x96

%if (0 == %%last_eight)
		vpsrldq		zmm13, %%TW1, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm15, %%TW1, 1
		vpxord		zmm15, zmm15, zmm14
%endif

	; AES rounds 1-3
%assign %%ROUND 1
%rep 3
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
%assign %%ROUND (%%ROUND + 1)
%endrep

%if (0 == %%last_eight)
		vpsrldq		zmm13, %%TW2, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm16, %%TW2, 1
		vpxord		zmm16, zmm16, zmm14
%endif

	; Remaining AES rounds
%rep (NROUNDS + 1 - 3)
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
%if %%ROUND == (NROUNDS + 1)
	vaesenclast  %%ST1, %%T0
	vaesenclast  %%ST2, %%T0
%else
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
%endif
%assign %%ROUND (%%ROUND + 1)
%endrep

	; xor Tweak values
	vpxorq    %%ST1, %%TW1
	vpxorq    %%ST2, %%TW2

	; load next Tweak values
%if (0 == %%last_eight)
	vmovdqa32  %%TW1, zmm15
	vmovdqa32  %%TW2, zmm16
%endif
%endmacro


; Encrypt 16 blocks in parallel
; generate next 16 tweak values
%macro  encrypt_by_16_zmm 10
%define %%ST1   %1      ; state 1
%define %%ST2   %2      ; state 2
%define %%ST3   %3      ; state 3
%define %%ST4   %4      ; state 4

%define %%TW1   %5      ; tweak 1
%define %%TW2   %6      ; tweak 2
%define %%TW3   %7      ; tweak 3
%define %%TW4   %8      ; tweak 4

%define %%T0    %9     ; Temp register
%define %%last_eight     %10

	; xor Tweak values + ARK
	vbroadcasti32x4 %%T0, [ptr_key1]
	vpternlogq    %%ST1, %%TW1, %%T0, 0x96
	vpternlogq    %%ST2, %%TW2, %%T0, 0x96
	vpternlogq    %%ST3, %%TW3, %%T0, 0x96
	vpternlogq    %%ST4, %%TW4, %%T0, 0x96


%if (0 == %%last_eight)
		vpsrldq		zmm13, %%TW3, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm15, %%TW3, 1
		vpxord		zmm15, zmm15, zmm14
%endif

	; AES rounds 1-3
%assign %%ROUND 1
%rep 3
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
	vaesenc  %%ST3, %%T0
	vaesenc  %%ST4, %%T0
%assign %%ROUND (%%ROUND + 1)
%endrep
%if (0 == %%last_eight)
		vpsrldq		zmm13, %%TW4, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm16, %%TW4, 1
		vpxord		zmm16, zmm16, zmm14
%endif
	; AES rounds 4-6
%rep 3
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
	vaesenc  %%ST3, %%T0
	vaesenc  %%ST4, %%T0
%assign %%ROUND (%%ROUND + 1)
%endrep
%if (0 == %%last_eight)
		vpsrldq		zmm13, zmm15, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm17, zmm15, 1
		vpxord		zmm17, zmm17, zmm14
%endif
	; AES rounds 7-9
%rep 3
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
	vaesenc  %%ST3, %%T0
	vaesenc  %%ST4, %%T0
%assign %%ROUND (%%ROUND + 1)
%endrep
%if (0 == %%last_eight)
		vpsrldq		zmm13, zmm16, 15
		vpclmulqdq	zmm14, zmm13, zpoly, 0
		vpslldq		zmm18, zmm16, 1
		vpxord		zmm18, zmm18, zmm14
%endif
	; Remaining AES rounds
%rep (NROUNDS + 1 - 9)
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
%if (%%ROUND == (NROUNDS + 1))
	vaesenclast  %%ST1, %%T0
	vaesenclast  %%ST2, %%T0
	vaesenclast  %%ST3, %%T0
	vaesenclast  %%ST4, %%T0
%else
	vaesenc  %%ST1, %%T0
	vaesenc  %%ST2, %%T0
	vaesenc  %%ST3, %%T0
	vaesenc  %%ST4, %%T0
%endif
%assign %%ROUND (%%ROUND + 1)
%endrep

	; xor Tweak values
	vpxorq    %%ST1, %%TW1
	vpxorq    %%ST2, %%TW2
	vpxorq    %%ST3, %%TW3
	vpxorq    %%ST4, %%TW4

	; load next Tweak values
	vmovdqa32  %%TW1, zmm15
	vmovdqa32  %%TW2, zmm16
	vmovdqa32  %%TW3, zmm17
	vmovdqa32  %%TW4, zmm18
%endmacro


section .text

mk_global FUNC, function, internal
FUNC:
	endbranch

	push		rbp
	mov		rbp, rsp
	sub		rsp, VARIABLE_OFFSET
	and		rsp, ~63

	mov		[_gpr + 8*0], rbx
%ifidn __OUTPUT_FORMAT__, win64
	mov		[_gpr + 8*1], rdi
	mov		[_gpr + 8*2], rsi

	vmovdqa		[_xmm + 16*0], xmm6
	vmovdqa		[_xmm + 16*1], xmm7
	vmovdqa		[_xmm + 16*2], xmm8
	vmovdqa		[_xmm + 16*3], xmm9
	vmovdqa		[_xmm + 16*4], xmm10
	vmovdqa		[_xmm + 16*5], xmm11
	vmovdqa		[_xmm + 16*6], xmm12
	vmovdqa		[_xmm + 16*7], xmm13
	vmovdqa		[_xmm + 16*8], xmm14
	vmovdqa		[_xmm + 16*9], xmm15
%endif

	mov		ghash_poly_8b, GHASH_POLY       ; load 0x87 to ghash_poly_8b


	vmovdqu64	XWORD(prev_tweak), [T_val]                   ; read initial Tweak value
	encrypt_T       XWORD(prev_tweak), ptr_key2


%ifidn __OUTPUT_FORMAT__, win64
	mov		ptr_plaintext, [rbp + 8 + 8*5]	; plaintext pointer
	mov             ptr_ciphertext, [rbp + 8 + 8*6]	; ciphertext pointer
%endif

	cmp		N_val, 128
	jb              _less_than_128_bytes

	vpbroadcastq	zpoly, ghash_poly_8b

	cmp		N_val, 256
	jae		_start_by16
	jmp		_start_by8

_do_last_n_blocks:
	cmp		N_val, 0
	je		_ret_

	cmp		N_val, (7*16)
	jae		_remaining_num_blocks_is_7

	cmp		N_val, (6*16)
	jae		_remaining_num_blocks_is_6

	cmp		N_val, (5*16)
	jae		_remaining_num_blocks_is_5

	cmp		N_val, (4*16)
	jae		_remaining_num_blocks_is_4

	cmp		N_val, (3*16)
	jae		_remaining_num_blocks_is_3

	cmp		N_val, (2*16)
	jae		_remaining_num_blocks_is_2

	cmp		N_val, (1*16)
	jae		_remaining_num_blocks_is_1

;; _remaining_num_blocks_is_0:
	vmovdqa		xmm8, xmm0
	vmovdqa		xmm0, xmm9
	jmp		_steal_cipher

_remaining_num_blocks_is_7:
	mov		tmp1, 0x0000ffff_ffffffff
	kmovq		k1, tmp1
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	zmm2 {k1}, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*7
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4] {k1}, zmm2
	add		ptr_ciphertext, 16*7

	vextracti32x4	xmm8, zmm2, 0x2
	vextracti32x4	xmm0, zmm10, 0x3
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_6:
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	ymm2, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*6
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4], ymm2
	add		ptr_ciphertext, 16*6

	vextracti32x4	xmm8, zmm2, 0x1
	vextracti32x4	xmm0, zmm10, 0x2
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_5:
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu		xmm2, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*5
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu		[ptr_ciphertext+16*4], xmm2
	add		ptr_ciphertext, 16*5

	vmovdqa		xmm8, xmm2
	vextracti32x4	xmm0, zmm10, 0x1
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_4:
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*4
	encrypt_by_four_zmm  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	add		ptr_ciphertext, 16*4

	vextracti32x4	xmm8, zmm1, 0x3
	vmovdqa64	zmm0, zmm10
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_3:
	mov		tmp1, -1
	shr		tmp1, 16
	kmovq		k1, tmp1
	vmovdqu8	zmm1{k1}, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*3
	encrypt_by_four_zmm  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_ciphertext+16*0]{k1}, zmm1
	add		ptr_ciphertext, 16*3

	vextracti32x4	xmm8, zmm1, 0x2
	vextracti32x4	xmm0, zmm9, 0x3
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_2:
	vmovdqu8	ymm1, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*2
	encrypt_by_four_zmm  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_ciphertext+16*0], ymm1
	add		ptr_ciphertext, 16*2

	vextracti32x4	xmm8, zmm1, 0x1
	vextracti32x4	xmm0, zmm9, 0x2
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher

_remaining_num_blocks_is_1:
	vmovdqu		xmm1, [ptr_plaintext]
	add		ptr_plaintext, 16
	encrypt_final xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm0, 1
	vmovdqu		[ptr_ciphertext], xmm1
	add		ptr_ciphertext, 16

	vmovdqa		xmm8, xmm1
	vextracti32x4	xmm0, zmm9, 1
	and		N_val, 15
	je		_ret_
	jmp		_steal_cipher


_start_by16:
	; Make first 7 tweak values (after initial tweak)
	vshufi32x4     	zmm0, prev_tweak, prev_tweak, 0x00
	vbroadcasti32x4	zmm8, [shufb_15_7]
	mov		DWORD(tmp1), 0xaa
	kmovq		k2, tmp1

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

	; Make next 8 tweak values by all x 2^8
	vpsrldq		zmm13, zmm9, 15
	vpclmulqdq	zmm14, zmm13, zpoly, 0
	vpslldq		zmm11, zmm9, 1
	vpxord		zmm11, zmm11, zmm14

	vpsrldq		zmm15, zmm10, 15
	vpclmulqdq	zmm16, zmm15, zpoly, 0
	vpslldq		zmm12, zmm10, 1
	vpxord		zmm12, zmm12, zmm16

_main_loop_run_16:
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	zmm2, [ptr_plaintext+16*4]
	vmovdqu8	zmm3, [ptr_plaintext+16*8]
	vmovdqu8	zmm4, [ptr_plaintext+16*12]
	add		ptr_plaintext, 256

	encrypt_by_16_zmm  zmm1, zmm2, zmm3, zmm4, zmm9, zmm10, zmm11, zmm12, zmm0, 0

	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4], zmm2
	vmovdqu8	[ptr_ciphertext+16*8], zmm3
	vmovdqu8	[ptr_ciphertext+16*12], zmm4
	add		ptr_ciphertext, 256
	sub		N_val, 256

	cmp		N_val, 256
	jae		_main_loop_run_16

	cmp		N_val, 128
	jae		_main_loop_run_8

	vextracti32x4	xmm0, zmm4, 0x3 ; keep last encrypted block
	jmp		_do_last_n_blocks

_start_by8:
	; Make first 7 tweak values (after initial tweak)
	vshufi32x4     	zmm0, prev_tweak, prev_tweak, 0x00
	vbroadcasti32x4	zmm8, [shufb_15_7]
	mov		DWORD(tmp1), 0xaa
	kmovq		k2, tmp1

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

_main_loop_run_8:
	; load plaintext
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	zmm2, [ptr_plaintext+16*4]
	add		ptr_plaintext, 128

	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 0

	; store ciphertext
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4], zmm2
	add		ptr_ciphertext, 128
	sub		N_val, 128

	cmp		N_val, 128
	jae		_main_loop_run_8

	vextracti32x4	xmm0, zmm2, 0x3 ; keep last encrypted block
	jmp		_do_last_n_blocks

_steal_cipher:
	; start cipher stealing simplified: xmm8 - last cipher block, xmm0 - next tweak
	vmovdqa		xmm2, xmm8

	; shift xmm8 to the left by 16-N_val bytes
	lea		twtempl, [vpshufb_shf_table]
	vmovdqu		xmm10, [twtempl+N_val]
	vpshufb		xmm8, xmm10

	vmovdqu		xmm3, [ptr_plaintext - 16 + N_val]
	vmovdqu		[ptr_ciphertext - 16 + N_val], xmm8

	; shift xmm3 to the right by 16-N_val bytes
	lea		twtempl, [vpshufb_shf_table +16]
	sub		twtempl, N_val
	vmovdqu		xmm10, [twtempl]
	vpxor		xmm10, [mask1]
	vpshufb		xmm3, xmm10

	vpblendvb	xmm8, xmm3, xmm2, xmm10

	; xor Tweak value and ARK round of last block encryption
	vpternlogq	xmm8, xmm0, [ptr_key1], 0x96

        ; AES rounds
%assign I 1
%rep NROUNDS
	vaesenc         xmm8, [ptr_key1 + 16*I]
%assign I (I + 1)
%endrep
	vaesenclast	xmm8, [ptr_key1 + 16*(NROUNDS+1)]

	; xor Tweak value
	vpxor		xmm8, xmm8, xmm0

	; store last ciphertext value
	vmovdqu		[ptr_ciphertext - 16], xmm8

_ret_:
%ifdef SAFE_DATA
        clear_all_zmms_asm
%else
        vzeroupper
%endif
	mov		rbx, [_gpr + 8*0]

%ifidn __OUTPUT_FORMAT__, win64
	mov		rdi, [_gpr + 8*1]
	mov		rsi, [_gpr + 8*2]

	vmovdqa		xmm6, [_xmm + 16*0]
	vmovdqa		xmm7, [_xmm + 16*1]
	vmovdqa		xmm8, [_xmm + 16*2]
	vmovdqa		xmm9, [_xmm + 16*3]
	vmovdqa		xmm10, [_xmm + 16*4]
	vmovdqa		xmm11, [_xmm + 16*5]
	vmovdqa		xmm12, [_xmm + 16*6]
	vmovdqa		xmm13, [_xmm + 16*7]
	vmovdqa		xmm14, [_xmm + 16*8]
	vmovdqa		xmm15, [_xmm + 16*9]
%endif

	mov		rsp, rbp
	pop		rbp
	ret


_less_than_128_bytes:
	vpbroadcastq	zpoly, ghash_poly_8b

	cmp		N_val, 16
	jb		_ret_

	vshufi32x4     	zmm0, prev_tweak, prev_tweak, 0x00
	vbroadcasti32x4	zmm8, [shufb_15_7]
	mov		DWORD(tmp1), 0xaa
	kmovq		k2, tmp1

	mov		tmp1, N_val
	and		tmp1, (7 << 4)
	cmp		tmp1, (6 << 4)
	je		_num_blocks_is_6
	cmp		tmp1, (5 << 4)
	je		_num_blocks_is_5
	cmp		tmp1, (4 << 4)
	je		_num_blocks_is_4
	cmp		tmp1, (3 << 4)
	je		_num_blocks_is_3
	cmp		tmp1, (2 << 4)
	je		_num_blocks_is_2
	cmp		tmp1, (1 << 4)
	je		_num_blocks_is_1

_num_blocks_is_7:
	; Make first 7 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

	mov		tmp1, 0x0000ffff_ffffffff
	kmovq		k1, tmp1
	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	zmm2 {k1}, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*7
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4] {k1}, zmm2
	add		ptr_ciphertext, 16*7

	vextracti32x4	xmm8, zmm2, 0x2
	vextracti32x4	xmm0, zmm10, 0x3
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher
_num_blocks_is_6:
	; Make first 7 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	ymm2, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*6
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4], ymm2
	add		ptr_ciphertext, 16*6

	vextracti32x4	xmm8, ymm2, 0x1
	vextracti32x4	xmm0, zmm10, 0x2
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher
_num_blocks_is_5:
	; Make first 7 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	vmovdqu8	xmm2, [ptr_plaintext+16*4]
	add		ptr_plaintext, 16*5
	encrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	vmovdqu8	[ptr_ciphertext+16*4], xmm2
	add		ptr_ciphertext, 16*5

        vmovdqa         xmm8, xmm2
	vextracti32x4	xmm0, zmm10, 0x1
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher
_num_blocks_is_4:
	; Make first 7 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	; Mult tweak by 2^{7, 6, 5, 4}
	vpsllvq		zmm5, zmm0, [const_dq7654]	; shift l 7,6,5,4
	vpsrlvq		zmm6, zmm1, [const_dq1234]	; shift r 1,2,3,4
	vpclmulqdq      zmm7, zmm6, zpoly, 0x00
	vpxorq		zmm5 {k2}, zmm5, zmm6		; tweaks shifted by 7-4
	vpxord		zmm10, zmm7, zmm5

	vmovdqu8	zmm1, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*4
	encrypt_by_four_zmm  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_ciphertext+16*0], zmm1
	add		ptr_ciphertext, 16*4

	vextracti32x4	xmm8, zmm1, 0x3
        vmovdqa         xmm0, xmm10
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher
_num_blocks_is_3:
	; Make first 3 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	mov		tmp1, 0x0000ffff_ffffffff
	kmovq		k1, tmp1
	vmovdqu8	zmm1{k1}, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*3
	encrypt_by_four_zmm  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_ciphertext+16*0]{k1}, zmm1
	add		ptr_ciphertext, 16*3

        vextracti32x4   xmm8, zmm1, 2
	vextracti32x4	xmm0, zmm9, 3
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher

_num_blocks_is_2:
	; Make first 3 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	vmovdqu8	ymm1, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16*2
	encrypt_by_four_zmm  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_ciphertext+16*0], ymm1
	add		ptr_ciphertext, 16*2

        vextracti32x4   xmm8, ymm1, 1
	vextracti32x4	xmm0, zmm9, 2
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher

_num_blocks_is_1:
	; Make first 3 tweak values (after initial tweak)

	; Mult tweak by 2^{3, 2, 1, 0}
	vpshufb		zmm1, zmm0, zmm8		; mov 15->0, 7->8
	vpsllvq		zmm4, zmm0, [const_dq3210]	; shift l 3,2,1,0
	vpsrlvq		zmm2, zmm1, [const_dq5678]	; shift r 5,6,7,8
	vpclmulqdq      zmm3, zmm2, zpoly, 0x00
	vpxorq		zmm4 {k2}, zmm4, zmm2		; tweaks shifted by 3-0
	vpxord		zmm9, zmm3, zmm4

	vmovdqu8	xmm1, [ptr_plaintext+16*0]
	add		ptr_plaintext, 16
	encrypt_by_four_zmm  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_ciphertext+16*0], xmm1
	add		ptr_ciphertext, 16

        vmovdqa         xmm8, xmm1
	vextracti32x4	xmm0, zmm9, 1
	and		N_val, 15               ; N_val = N_val mod 16
	je		_ret_
	jmp		_steal_cipher
section .data
align 16

vpshufb_shf_table:
; use these values for shift constants for the vpshufb instruction
; different alignments result in values as shown:
;       dq 0x8887868584838281, 0x008f8e8d8c8b8a89 ; shl 15 (16-1) / shr1
;       dq 0x8988878685848382, 0x01008f8e8d8c8b8a ; shl 14 (16-3) / shr2
;       dq 0x8a89888786858483, 0x0201008f8e8d8c8b ; shl 13 (16-4) / shr3
;       dq 0x8b8a898887868584, 0x030201008f8e8d8c ; shl 12 (16-4) / shr4
;       dq 0x8c8b8a8988878685, 0x04030201008f8e8d ; shl 11 (16-5) / shr5
;       dq 0x8d8c8b8a89888786, 0x0504030201008f8e ; shl 10 (16-6) / shr6
;       dq 0x8e8d8c8b8a898887, 0x060504030201008f ; shl 9  (16-7) / shr7
;       dq 0x8f8e8d8c8b8a8988, 0x0706050403020100 ; shl 8  (16-8) / shr8
;       dq 0x008f8e8d8c8b8a89, 0x0807060504030201 ; shl 7  (16-9) / shr9
;       dq 0x01008f8e8d8c8b8a, 0x0908070605040302 ; shl 6  (16-10) / shr10
;       dq 0x0201008f8e8d8c8b, 0x0a09080706050403 ; shl 5  (16-11) / shr11
;       dq 0x030201008f8e8d8c, 0x0b0a090807060504 ; shl 4  (16-12) / shr12
;       dq 0x04030201008f8e8d, 0x0c0b0a0908070605 ; shl 3  (16-13) / shr13
;       dq 0x0504030201008f8e, 0x0d0c0b0a09080706 ; shl 2  (16-14) / shr14
;       dq 0x060504030201008f, 0x0e0d0c0b0a090807 ; shl 1  (16-15) / shr15
dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
dq 0x0706050403020100, 0x000e0d0c0b0a0908

mask1:
dq 0x8080808080808080, 0x8080808080808080

const_dq3210: dq 0, 0, 1, 1, 2, 2, 3, 3
const_dq5678: dq 8, 8, 7, 7, 6, 6, 5, 5
const_dq7654: dq 4, 4, 5, 5, 6, 6, 7, 7
const_dq1234: dq 4, 4, 3, 3, 2, 2, 1, 1

shufb_15_7: db 15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
