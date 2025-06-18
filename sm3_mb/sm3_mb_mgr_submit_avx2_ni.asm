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

%include "sm3_job.asm"
%include "memcpy.asm"
%include "sm3_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

extern sm3_update_ni_x1

[bits 64]
default rel
section .text

%ifidn __OUTPUT_FORMAT__, elf64
; Linux register definitions
%define arg1    rdi
%define arg2    rsi
%define arg3	rdx

%else
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx
%define arg3	r8

%endif

; Common definitions
%define job     arg2

%define job_rax rax

; ISAL_SM3_JOB* _sm3_mb_mgr_submit_avx2_ni(ISAL_SM3_MB_JOB_MGR *state, ISAL_SM3_JOB *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
mk_global _sm3_mb_mgr_submit_avx2_ni, function, internal
_sm3_mb_mgr_submit_avx2_ni:
	endbranch

    	mov 	job_rax, job

    	lea	arg1, [job_rax + _result_digest]
    	mov	arg2, [job_rax + _buffer]
    	mov 	arg3, [job_rax + _len]

	; arg1 contains digest pointer
    	; arg2 contains buffer pointer
    	; arg3 contains num_blocks
	call	sm3_update_ni_x1

    	mov 	dword [job_rax + _status], ISAL_STS_COMPLETED

	ret

%endif ; HAVE_AS_KNOWS_SHA512NI