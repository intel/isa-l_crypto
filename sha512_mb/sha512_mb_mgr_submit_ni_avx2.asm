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

%ifidn __OUTPUT_FORMAT__, elf64
; Linux register definitions
%define arg1    rdi
%define arg2    rsi

; idx needs to be other than arg1, arg2, rbx, r12
%define idx             rdx

%else
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

; idx needs to be other than arg1, arg2, rbx, r12
%define idx             rsi

%endif

; Common definitions
%define state   arg1
%define job     arg2
%define len2    arg2

%define p               r11

%define unused_lanes    r8

%define job_rax         rax
%define len             rax

%define lane            r9

%define lens0           r8

%define tmp             r9
%define lens1           r9

%define lane_data       r10

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

; ISAL_SHA512_JOB* _sha512_mb_mgr_submit_ni_avx2(ISAL_SHA512_MB_JOB_MGR *state, ISAL_SHA512_JOB *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
mk_global _sha512_mb_mgr_submit_ni_avx2, function, internal
_sha512_mb_mgr_submit_ni_avx2:
	endbranch

	FUNC_SAVE

	mov     unused_lanes, [state + _unused_lanes]
	movzx   lane, BYTE(unused_lanes)
	shr     unused_lanes, 8
	imul    lane_data, lane, _LANE_DATA_size
	mov     dword [job + _status], ISAL_STS_BEING_PROCESSED
	lea     lane_data, [state + _ldata + lane_data]
	mov     [state + _unused_lanes], unused_lanes
	mov     DWORD(len), [job + _len]

	mov     [lane_data + _job_in_lane], job
	mov     [state + _lens + 4 + 8*lane], DWORD(len)


	; Load digest words from result_digest
	vmovdqa	ymm0, [job + _result_digest + 0*16]
	vmovdqa	ymm1, [job + _result_digest + 2*16]

	shl 	lane, 6
	vmovdqu [state + _args_digest + lane], ymm0
	vmovdqu [state + _args_digest + lane + 32], ymm1
	shr 	lane, 6

	mov     p, [job + _buffer]
	mov     [state + _args_data_ptr + 8*lane], p

	add     dword [state + _num_lanes_inuse], 1
	cmp     unused_lanes, 0xff
	jne     return_null

start_loop:

	; Find min length
	mov     lens0, [state + _lens + 0*8]
	mov     idx, lens0
	mov     lens1, [state + _lens + 1*8]
	cmp     lens1, lens0
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

        push 	idx ; save idx value

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

	mov     unused_lanes, [state + _unused_lanes]
	mov     qword [lane_data + _job_in_lane], 0
	mov     dword [job_rax + _status], ISAL_STS_COMPLETED
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

%endif ; HAVE_AS_KNOWS_SHA512NI

;; Needed to avoid linker issues on Windows with VS 2019
section .rodata
    b db 0x01