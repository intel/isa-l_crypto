;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2024 Intel Corporation All rights reserved.
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
; XTS decrypt function with 128-bit AES
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
%define FUNC _XTS_AES_128_dec_expanded_key_vaes
%endif
%define GHASH_POLY 0x87

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void _XTS_AES_128_dec_expanded_key_vaes(
;               UINT8 *k2,      // key used for tweaking, 16*11 bytes
;               UINT8 *k1,      // key used for "ECB" encryption, 16*11 bytes
;               UINT8 *TW_initial,      // initial tweak value, 16 bytes
;               UINT64 N,       // sector size, in bytes
;               const UINT8 *ct,        // ciphertext sector input data
;               UINT8 *pt);     // plaintext sector output data
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; arguments for input parameters
%ifidn __OUTPUT_FORMAT__, elf64
	%xdefine ptr_key2 rdi
	%xdefine ptr_key1 rsi
	%xdefine T_val rdx
	%xdefine N_val rcx
	%xdefine ptr_ciphertext r8
	%xdefine ptr_plaintext r9
%else
	%xdefine ptr_key2 rcx
	%xdefine ptr_key1 rdx
	%xdefine T_val r8
	%xdefine N_val r9
	%xdefine ptr_ciphertext r10; [rsp + VARIABLE_OFFSET + 8*5]
	%xdefine ptr_plaintext r11; [rsp + VARIABLE_OFFSET + 8*6]
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

; Decrypt 4 blocks in parallel
%macro  decrypt_up_to_four_blocks 3-4
%define %%ST1   %1      ; state 1
%define %%TW1   %2      ; tweak 1
%define %%T0    %3      ; Temp register
%define %%XMM   %4      ; if set, ST1 and TW1 are XMM registers

	; xor Tweak values + ARK
%if %0 == 4
        vpternlogq      %%ST1, %%TW1, [ptr_key1], 0x96
%else
	vbroadcasti32x4 %%T0, [ptr_key1]
	vpternlogq      %%ST1, %%TW1, %%T0, 0x96
%endif

	; AES rounds
%assign %%ROUND 1
%rep (NROUNDS + 1)
%if %0 == 4
        vmovdqu64       %%T0, [ptr_key1 + 16*%%ROUND]
%else
	vbroadcasti32x4 %%T0, [ptr_key1 + 16*%%ROUND]
%endif
%if %%ROUND == (NROUNDS + 1)
	vaesdeclast  %%ST1, %%T0
%else
	vaesdec  %%ST1, %%T0
%endif
%assign %%ROUND (%%ROUND + 1)
%endrep

	; xor Tweak values
	vpxorq    %%ST1, %%TW1

%endmacro


; Encrypt 8 blocks in parallel
; generate next 8 tweak values
%macro  decrypt_by_eight_zmm 6
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
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
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
	vaesdeclast  %%ST1, %%T0
	vaesdeclast  %%ST2, %%T0
%else
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
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


; Decrypt 16 blocks in parallel
; generate next 16 tweak values
%macro  decrypt_by_16_zmm 10
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
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
	vaesdec  %%ST3, %%T0
	vaesdec  %%ST4, %%T0
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
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
	vaesdec  %%ST3, %%T0
	vaesdec  %%ST4, %%T0
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
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
	vaesdec  %%ST3, %%T0
	vaesdec  %%ST4, %%T0
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
	vaesdeclast  %%ST1, %%T0
	vaesdeclast  %%ST2, %%T0
	vaesdeclast  %%ST3, %%T0
	vaesdeclast  %%ST4, %%T0
%else
	vaesdec  %%ST1, %%T0
	vaesdec  %%ST2, %%T0
	vaesdec  %%ST3, %%T0
	vaesdec  %%ST4, %%T0
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
	mov		ptr_ciphertext, [rbp + 8 + 8*5]	; ciphertext pointer
	mov             ptr_plaintext, [rbp + 8 + 8*6]	; plaintext pointer
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
	vmovdqu		xmm1, xmm5 ; xmm5 contains last full block to decrypt with next teawk
	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu		[ptr_plaintext - 16], xmm1
	vmovdqa		xmm8, xmm1

	; Calc previous tweak
	mov		tmp1, 1
	kmovq		k1, tmp1
	vpsllq		xmm13, xmm9, 63
	vpsraq		xmm14, xmm13, 63
	vpandq		xmm5, xmm14, XWORD(zpoly)
	vpxorq		xmm9 {k1}, xmm9, xmm5
	vpsrldq		xmm10, xmm9, 8
	vpshrdq		xmm0, xmm9, xmm10, 1
	vpslldq		xmm13, xmm13, 8
	vpxorq		xmm0, xmm0, xmm13
	jmp		_steal_cipher

_remaining_num_blocks_is_7:
	mov		tmp1, 0x0000ffff_ffffffff
	kmovq		k1, tmp1
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	zmm2 {k1}, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*7

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_7

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4] {k1}, zmm2
	add		ptr_plaintext, 16*7

        jmp             _ret_

_remaining_num_blocks_is_6:
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	ymm2, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*6

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_6

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], ymm2
	add		ptr_plaintext, 16*6

        jmp             _ret_

_remaining_num_blocks_is_5:
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu		xmm2, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*5

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_5

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu		[ptr_plaintext+16*4], xmm2
	add		ptr_plaintext, 16*5

        jmp             _ret_

_remaining_num_blocks_is_4:
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*4

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_4

	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	add		ptr_plaintext, 16*4

        jmp             _ret_

_remaining_num_blocks_is_3:
	mov		tmp1, 0x0000ffff_ffffffff
	kmovq		k1, tmp1
	vmovdqu8	zmm1{k1}, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*3

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_3

	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0]{k1}, zmm1
	add		ptr_plaintext, 16*3

        jmp             _ret_

_remaining_num_blocks_is_2:
	vmovdqu8	ymm1, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*2

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_2

	decrypt_up_to_four_blocks  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_plaintext+16*0], ymm1
	add		ptr_plaintext, 16*2

        jmp             _ret_

_remaining_num_blocks_is_1:
	vmovdqu		xmm1, [ptr_ciphertext]
	add		ptr_ciphertext, 16

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_1

	decrypt_up_to_four_blocks  xmm1, xmm9, xmm0, 1
	vmovdqu		[ptr_plaintext], xmm1
	add		ptr_plaintext, 16

        jmp             _ret_

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
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	zmm2, [ptr_ciphertext+16*4]
	vmovdqu8	zmm3, [ptr_ciphertext+16*8]
	vmovdqu8	zmm4, [ptr_ciphertext+16*12]
	vmovdqu8	xmm5, [ptr_ciphertext+16*15] 	; Save last full block in case this is the last iteration
	add		ptr_ciphertext, 256

	decrypt_by_16_zmm  zmm1, zmm2, zmm3, zmm4, zmm9, zmm10, zmm11, zmm12, zmm0, 0

	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], zmm2
	vmovdqu8	[ptr_plaintext+16*8], zmm3
	vmovdqu8	[ptr_plaintext+16*12], zmm4
	add		ptr_plaintext, 256
	sub		N_val, 256

	cmp		N_val, 256
	jae		_main_loop_run_16

	cmp		N_val, 128
	jae		_main_loop_run_8

	vextracti32x4	xmm0, zmm4, 0x3 ; keep last decrypted block
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
	; load ciphertext
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	zmm2, [ptr_ciphertext+16*4]
	vmovdqu8	xmm5, [ptr_ciphertext+16*7] 	; Save last full block in case this is the last iteration
	add		ptr_ciphertext, 128

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 0

	; store plaintext
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], zmm2
	add		ptr_plaintext, 128
	sub		N_val, 128

	cmp		N_val, 128
	jae		_main_loop_run_8

	vextracti32x4	xmm0, zmm2, 0x3 ; keep last decrypted block
	jmp		_do_last_n_blocks

_steal_cipher:
	; start cipher stealing simplified: xmm8 - last cipher block, xmm0 - next tweak
	vmovdqa		xmm2, xmm8

	; shift xmm8 to the left by 16-N_val bytes
	lea		twtempl, [vpshufb_shf_table]
	vmovdqu		xmm10, [twtempl+N_val]
	vpshufb		xmm8, xmm10

	vmovdqu		xmm3, [ptr_ciphertext - 16 + N_val]
	vmovdqu		[ptr_plaintext - 16 + N_val], xmm8

	; shift xmm3 to the right by 16-N_val bytes
	lea		twtempl, [vpshufb_shf_table +16]
	sub		twtempl, N_val
	vmovdqu		xmm10, [twtempl]
	vpxor		xmm10, [mask1]
	vpshufb		xmm3, xmm10

	vpblendvb	xmm8, xmm3, xmm2, xmm10

	; xor Tweak value and ARK round of last block decryption
	vpternlogq	xmm8, xmm0, [ptr_key1], 0x96

        ; AES rounds
%assign I 1
%rep NROUNDS
	vaesdec         xmm8, [ptr_key1 + 16*I]
%assign I (I + 1)
%endrep
	vaesdeclast	xmm8, [ptr_key1 + 16*(NROUNDS+1)]

	; xor Tweak value
	vpxor		xmm8, xmm8, xmm0

	; store last plaintext value
	vmovdqu		[ptr_plaintext - 16], xmm8

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
	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	zmm2 {k1}, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*7

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_7

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4] {k1}, zmm2
	add		ptr_plaintext, 16*7

        jmp             _ret_
_steal_cipher_7:
        vshufi32x4      zmm10, zmm10, zmm10, 0b_1011_0100
	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4] {k1}, zmm2
	add		ptr_plaintext, 16*7

	vextracti32x4	xmm8, zmm2, 0x2
	vextracti32x4	xmm0, zmm10, 0x3
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

	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	ymm2, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*6

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_6

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], ymm2
	add		ptr_plaintext, 16*6

        jmp             _ret_
_steal_cipher_6:
        vshufi32x4      zmm10, zmm10, zmm10, 0b_1101_1000

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], ymm2
	add		ptr_plaintext, 16*6

	vextracti32x4	xmm8, ymm2, 0x1
	vextracti32x4	xmm0, zmm10, 0x2
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

	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	vmovdqu8	xmm2, [ptr_ciphertext+16*4]
	add		ptr_ciphertext, 16*5

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_5

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], xmm2
	add		ptr_plaintext, 16*5

        jmp             _ret_
_steal_cipher_5:
        vshufi32x4      zmm10, zmm10, zmm10, 0b_1110_0001

	decrypt_by_eight_zmm  zmm1, zmm2, zmm9, zmm10, zmm0, 1
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	vmovdqu8	[ptr_plaintext+16*4], xmm2
	add		ptr_plaintext, 16*5

        vmovdqa         xmm8, xmm2
	vextracti32x4	xmm0, zmm10, 0x1
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

	vmovdqu8	zmm1, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*4

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_4

	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	add		ptr_plaintext, 16*4

        jmp             _ret_
_steal_cipher_4:
        vmovdqa         xmm12, xmm10
        vextracti32x4   xmm10, zmm9, 3
        vinserti32x4    zmm9, xmm12, 3
	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0], zmm1
	add		ptr_plaintext, 16*4

	vextracti32x4	xmm8, zmm1, 0x3
        vmovdqa         xmm0, xmm10
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
	vmovdqu8	zmm1{k1}, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*3

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_3

	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0]{k1}, zmm1
	add		ptr_plaintext, 16*3

        jmp             _ret_

_steal_cipher_3:
        vshufi32x4      zmm9, zmm9, zmm9, 0b_1011_0100
	decrypt_up_to_four_blocks  zmm1, zmm9, zmm0
	vmovdqu8	[ptr_plaintext+16*0]{k1}, zmm1
	add		ptr_plaintext, 16*3

        vextracti32x4   xmm8, zmm1, 2
	vextracti32x4	xmm0, zmm9, 3
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

	vmovdqu8	ymm1, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16*2

	and		N_val, 15               ; n_val = n_val mod 16
	jne		_steal_cipher_2

	decrypt_up_to_four_blocks  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_plaintext+16*0], ymm1
	add		ptr_plaintext, 16*2
        jmp             _ret_

_steal_cipher_2:
        vshufi32x4      zmm9, zmm9, zmm9, 0b_1101_1000
	decrypt_up_to_four_blocks  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_plaintext+16*0], ymm1
	add		ptr_plaintext, 16*2

        vextracti32x4   xmm8, ymm1, 1
	vextracti32x4	xmm0, zmm9, 2
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

	vmovdqu8	xmm1, [ptr_ciphertext+16*0]
	add		ptr_ciphertext, 16

	and		N_val, 15               ; N_val = N_val mod 16
	jne		_steal_cipher_1

	decrypt_up_to_four_blocks  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_plaintext+16*0], xmm1
	add		ptr_plaintext, 16
        jmp             _ret_
_steal_cipher_1:
        vperm2i128      ymm9, ymm9, ymm9, 0x01 ; Swap last two tweaks
	decrypt_up_to_four_blocks  ymm1, ymm9, ymm0
	vmovdqu8	[ptr_plaintext+16*0], xmm1
	add		ptr_plaintext, 16

        vmovdqa         xmm8, xmm1
	vextracti32x4	xmm0, zmm9, 1
	jmp		_steal_cipher
section .data
align 16

vpshufb_shf_table:
; use these values for shift constants for the vpshufb instruction
; different alignments result in values as shown:
dq 0x8786858483828100, 0x8f8e8d8c8b8a8988
dq 0x0706050403020100, 0x000e0d0c0b0a0908

mask1:
dq 0x8080808080808080, 0x8080808080808080

const_dq3210: dq 0, 0, 1, 1, 2, 2, 3, 3
const_dq5678: dq 8, 8, 7, 7, 6, 6, 5, 5
const_dq7654: dq 4, 4, 5, 5, 6, 6, 7, 7
const_dq1234: dq 4, 4, 3, 3, 2, 2, 1, 1

shufb_15_7: db 15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
