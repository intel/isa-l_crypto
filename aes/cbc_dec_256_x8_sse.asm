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

; routine to do AES cbc decrypt on 16n bytes doing AES by 8
; XMM registers are clobbered. Saving/restoring must be done at a higher level

; void aes_cbc_dec_256_sse(void     *in,
;                          uint8_t  *IV,
;                          uint8_t   keys,
;                          void     *out,
;                          uint64_t  len_bytes);
;
; arg 1: IN:   pointer to input (cipher text)
; arg 2: IV:   pointer to IV
; arg 3: KEYS: pointer to keys
; arg 4: OUT:  pointer to output (plain text)
; arg 5: LEN:  length in bytes (multiple of 16)
;
%include "reg_sizes.asm"
%include "clear_regs.inc"

%ifidn __OUTPUT_FORMAT__, elf64
%define arg1	        rdi
%define arg2	        rsi
%define arg3	        rdx
%define arg4	        rcx
%define arg5            r8
%define func(x) x:
%define FUNC_SAVE
%define FUNC_RESTORE
%endif

%ifidn __OUTPUT_FORMAT__, win64
%define arg1	        rcx
%define arg2	        rdx
%define arg3	        r8
%define arg4	        r9
%define arg5            rax
%define PS		8
%define stack_size	10*16 + 1*8	; must be an odd multiple of 8
%define arg(x)		[rsp + stack_size + PS + PS*x]

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
	end_prolog
	mov	arg5, arg(4)
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
	add	rsp, stack_size
%endmacro

%endif

%include "include/aes_cbc_dec_by8_sse.inc"

section .text

;; aes_cbc_dec_256_sse(void *in, void *IV, void *keys, void *out, UINT64 num_bytes)
mk_global aes_cbc_dec_256_sse, function
func(aes_cbc_dec_256_sse)
	endbranch
	FUNC_SAVE

        AES_CBC_DEC arg1, arg2, arg3, arg4, arg5, r10, 13

	FUNC_RESTORE
	ret

endproc_frame
