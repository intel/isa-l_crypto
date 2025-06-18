;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2025 Intel Corporation All rights reserved.
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
%ifdef HAVE_AS_KNOWS_SHA512NI

%include "sha512_job.asm"
%include "sha512_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

extern sha512_ni_x2_avx2

[bits 64]
default rel
section .text

%ifidn __OUTPUT_FORMAT__, elf64
; LINUX register definitions
%define arg1    rdi
%define arg2    rsi

; idx needs to be other than arg1, arg2, rbx, r12
%define idx     rdx
%else
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

; idx needs to be other than arg1, arg2, rbx, r12
%define idx     rsi
%endif

; Common definitions
%define state   arg1
%define len2    arg2

%define unused_lanes    r10
%define lane_data       r10

%define job_rax         rax
%define tmp             rax

%define tmp2		r11

%define lens0           r8
%define lens1           r9

%define APPEND(a,b) a %+ b

%define GP_STORAGE      1*8
%ifndef LINUX
%define XMM_STORAGE     10*16
%else
%define XMM_STORAGE     0
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE

%macro FUNC_SAVE 0
    mov     r11, rsp
    sub     rsp, VARIABLE_OFFSET
    and     rsp, ~15    ; align rsp to 32 bytes
%ifndef LINUX
    vmovdqa [rsp + 0*16], xmm6
    vmovdqa [rsp + 1*16], xmm7
    vmovdqa [rsp + 2*16], xmm8
    vmovdqa [rsp + 3*16], xmm9
    vmovdqa [rsp + 4*16], xmm10
    vmovdqa [rsp + 5*16], xmm11
    vmovdqa [rsp + 6*16], xmm12
    vmovdqa [rsp + 7*16], xmm13
    vmovdqa [rsp + 8*16], xmm14
    vmovdqa [rsp + 9*16], xmm15
%endif ; LINUX
    mov     [rsp + XMM_STORAGE], r11 ;; rsp pointer
%endmacro

%macro FUNC_RESTORE 0
%ifndef LINUX
    vmovdqa xmm6,  [rsp + 0*16]
    vmovdqa xmm7,  [rsp + 1*16]
    vmovdqa xmm8,  [rsp + 2*16]
    vmovdqa xmm9,  [rsp + 3*16]
    vmovdqa xmm10, [rsp + 4*16]
    vmovdqa xmm11, [rsp + 5*16]
    vmovdqa xmm12, [rsp + 6*16]
    vmovdqa xmm13, [rsp + 7*16]
    vmovdqa xmm14, [rsp + 8*16]
    vmovdqa xmm15, [rsp + 9*16]
%endif ; LINUX
    mov     rsp,   [rsp + XMM_STORAGE] ;; rsp pointer
%endmacro

; ISAL_SHA512_JOB* _sha512_mb_mgr_flush_avx(ISAL_SHA512_MB_JOB_MGR *state)
; arg 1 : rcx : state
mk_global _sha512_mb_mgr_flush_ni_avx2, function, internal
_sha512_mb_mgr_flush_ni_avx2:
	endbranch

	FUNC_SAVE

	mov     unused_lanes, [state + _unused_lanes]
	bt      unused_lanes, 16+7
	jc      return_null

	; find a lane with a non-null job
	xor     idx, idx
	cmp     qword [state + _ldata + 1 * _LANE_DATA_size + _job_in_lane], 0
	cmovne  idx, [one]

	; copy idx to empty lanes
copy_lane_data:
	mov     tmp, [state + _args + _data_ptr + 8*idx]

	mov 	tmp2, idx
	xor 	tmp2, 1
	mov     [state + _args + _data_ptr + 8*tmp2], tmp
	mov     dword [state + _lens + 4 + 8*tmp2], 0xFFFFFFFF

	; Find min length
	mov     lens0, [state + _lens + 0*8]
	mov     idx, lens0
	mov     lens1, [state + _lens + 1*8]
	cmp     lens1, idx
	cmovb   idx, lens1

	mov     len2, idx
	and     idx, 0xF
	and     len2, ~0xFF
	jz      len_is_0

	sub     lens0, len2
	sub     lens1, len2
	shr     len2, 32
	mov     [state + _lens + 0*8], lens0
	mov     [state + _lens + 1*8], lens1

        push 	idx

	; "state" and "args" are the same address, arg1
	; len is arg2
	call    sha512_ni_x2_avx2
	; state is intact

        pop 	idx ; restore idx value

len_is_0:
	; process completed job "idx"
	imul    lane_data, idx, _LANE_DATA_size
	lea     lane_data, [state + _ldata + lane_data]

	mov     job_rax, [lane_data + _job_in_lane]
	mov     qword [lane_data + _job_in_lane], 0
	mov     dword [job_rax + _status], ISAL_STS_COMPLETED
	mov     unused_lanes, [state + _unused_lanes]
	shl     unused_lanes, 8
	or      unused_lanes, idx
	mov     [state + _unused_lanes], unused_lanes

	sub     dword [state + _num_lanes_inuse], 1

	shl 	idx, 6
	vmovdqu	ymm0, [state + _args_digest + idx]
	vmovdqu	ymm1, [state + _args_digest + idx + 32]

	vmovdqa [job_rax + _result_digest + 0*16], ymm0
	vmovdqa [job_rax + _result_digest + 2*16], ymm1

return:
	FUNC_RESTORE
	ret

return_null:
	xor     job_rax, job_rax
	jmp     return

section .rodata

align 8
one:    dq  1

%endif ; HAVE_AS_KNOWS_SHA512NI
