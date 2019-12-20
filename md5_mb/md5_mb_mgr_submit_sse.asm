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

%include "md5_job.asm"
%include "md5_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

extern md5_mb_x4x2_sse
default rel

%if 1
%ifidn __OUTPUT_FORMAT__, win64
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

%else
; UN*X register definitions
%define arg1    rdi
%define arg2    rsi

%endif

; Common definitions
%define state   arg1
%define job     arg2
%define len2    arg2

; idx must be a register not clobberred by md5_mb_x4x2_sse
%define idx             r8

%define p               r9

%define unused_lanes    rbx

%define job_rax         rax
%define len             rax

%define lane            r10

%define lane_data       r11

%endif ; if 1

; STACK_SPACE needs to be an odd multiple of 8
%define STACK_SPACE     8*8 + 16*10 + 8

; JOB* submit_job(MB_MGR *state, JOB_MD5 *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
global md5_mb_mgr_submit_sse:function
md5_mb_mgr_submit_sse:

        sub     rsp, STACK_SPACE
	; we need to save/restore all GPRs because lower layer clobbers them
        mov     [rsp + 8*0], rbx
        mov     [rsp + 8*1], rbp
        mov     [rsp + 8*2], r12
        mov     [rsp + 8*3], r13
        mov     [rsp + 8*4], r14
        mov     [rsp + 8*5], r15
%ifidn __OUTPUT_FORMAT__, win64
        mov     [rsp + 8*6], rsi
        mov     [rsp + 8*7], rdi
        movdqa  [rsp + 8*8 + 16*0], xmm6
        movdqa  [rsp + 8*8 + 16*1], xmm7
        movdqa  [rsp + 8*8 + 16*2], xmm8
        movdqa  [rsp + 8*8 + 16*3], xmm9
        movdqa  [rsp + 8*8 + 16*4], xmm10
        movdqa  [rsp + 8*8 + 16*5], xmm11
        movdqa  [rsp + 8*8 + 16*6], xmm12
        movdqa  [rsp + 8*8 + 16*7], xmm13
        movdqa  [rsp + 8*8 + 16*8], xmm14
        movdqa  [rsp + 8*8 + 16*9], xmm15
%endif

        mov     unused_lanes, [state + _unused_lanes]
        mov     lane, unused_lanes
	and     lane, 0xF
        shr     unused_lanes, 4
        imul    lane_data, lane, _LANE_DATA_size
        mov     dword [job + _status], STS_BEING_PROCESSED
        lea     lane_data, [state + _ldata + lane_data]
        mov     [state + _unused_lanes], unused_lanes
        mov     DWORD(len), [job + _len]

	shl	len, 4
	or	len, lane

        mov     [lane_data + _job_in_lane], job
        mov     [state + _lens + 4*lane], DWORD(len)

	; Load digest words from result_digest
	movdqu	xmm0, [job + _result_digest + 0*16]
        movd    [state + _args_digest + 4*lane + 0*32], xmm0
        pextrd  [state + _args_digest + 4*lane + 1*32], xmm0, 1
        pextrd  [state + _args_digest + 4*lane + 2*32], xmm0, 2
        pextrd  [state + _args_digest + 4*lane + 3*32], xmm0, 3

        mov     p, [job + _buffer]
        mov     [state + _args_data_ptr + 8*lane], p

	add     dword [state + _num_lanes_inuse], 1
        cmp     unused_lanes, 0xF
        jne     return_null

start_loop:
        ; Find min length
	movdqa	xmm0, [state + _lens + 0*16]
        movdqa	xmm1, [state + _lens + 1*16]

	movdqa	xmm2, xmm0
        pminud 	xmm2, xmm1        ; xmm2 has {D,C,B,A}
        palignr xmm3, xmm2, 8     ; xmm3 has {x,x,D,C}
        pminud	xmm2, xmm3        ; xmm2 has {x,x,E,F}
        palignr xmm3, xmm2, 4     ; xmm3 has {x,x,x,E}
        pminud	xmm2, xmm3        ; xmm2 has min value in low dword

        movd   DWORD(idx), xmm2
        mov	len2, idx
        and	idx, 0xF
        shr	len2, 4
        jz	len_is_0

        pand   xmm2, [rel clear_low_nibble]
        pshufd xmm2, xmm2, 0

        psubd  xmm0, xmm2
        psubd  xmm1, xmm2

        movdqa [state + _lens + 0*16], xmm0
        movdqa [state + _lens + 1*16], xmm1

        ; "state" and "args" are the same address, arg1
        ; len is arg2
        call    md5_mb_x4x2_sse
        ; state and idx are intact

len_is_0:
        ; process completed job "idx"
        imul    lane_data, idx, _LANE_DATA_size
        lea     lane_data, [state + _ldata + lane_data]

        mov     job_rax, [lane_data + _job_in_lane]
        mov     unused_lanes, [state + _unused_lanes]
        mov     qword [lane_data + _job_in_lane], 0
        mov     dword [job_rax + _status], STS_COMPLETED
        shl     unused_lanes, 4
        or      unused_lanes, idx
        mov     [state + _unused_lanes], unused_lanes

	mov	dword [state + _lens + 4*idx], 0xFFFFFFFF
	sub     dword [state + _num_lanes_inuse], 1

        movd    xmm0, [state + _args_digest + 4*idx + 0*32]
        pinsrd  xmm0, [state + _args_digest + 4*idx + 1*32], 1
        pinsrd  xmm0, [state + _args_digest + 4*idx + 2*32], 2
        pinsrd  xmm0, [state + _args_digest + 4*idx + 3*32], 3

        movdqa  [job_rax + _result_digest + 0*16], xmm0

return:

%ifidn __OUTPUT_FORMAT__, win64
        movdqa  xmm6, [rsp + 8*8 + 16*0]
        movdqa  xmm7, [rsp + 8*8 + 16*1]
        movdqa  xmm8, [rsp + 8*8 + 16*2]
        movdqa  xmm9, [rsp + 8*8 + 16*3]
        movdqa  xmm10, [rsp + 8*8 + 16*4]
        movdqa  xmm11, [rsp + 8*8 + 16*5]
        movdqa  xmm12, [rsp + 8*8 + 16*6]
        movdqa  xmm13, [rsp + 8*8 + 16*7]
        movdqa  xmm14, [rsp + 8*8 + 16*8]
        movdqa  xmm15, [rsp + 8*8 + 16*9]
        mov     rsi, [rsp + 8*6]
        mov     rdi, [rsp + 8*7]
%endif
        mov     rbx, [rsp + 8*0]
        mov     rbp, [rsp + 8*1]
        mov     r12, [rsp + 8*2]
        mov     r13, [rsp + 8*3]
        mov     r14, [rsp + 8*4]
        mov     r15, [rsp + 8*5]

        add     rsp, STACK_SPACE

        ret

return_null:
        xor     job_rax, job_rax
        jmp     return


section .data align=16

align 16
clear_low_nibble:
	dq 0x00000000FFFFFFF0, 0x0000000000000000
