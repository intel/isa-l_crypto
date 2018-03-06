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

%include "sha1_job.asm"
%include "memcpy.asm"
%include "sha1_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

extern sha1_mb_x8_avx2

%ifidn __OUTPUT_FORMAT__, elf64
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; LINUX register definitions
%define arg1    rdi ; rcx
%define arg2    rsi ; rdx

%define size_offset     rcx ; rdi
%define tmp2            rcx ; rdi

%define extra_blocks    rdx
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%else

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

%define size_offset     rdi
%define tmp2            rdi

%define extra_blocks    rsi
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endif

; Common definitions
%define state   arg1
%define job     arg2
%define len2    arg2
%define p2      arg2

; idx must be a register not clobberred by sha1_x8_avx2
%define idx             r8
%define last_len        r8

%define p               r11
%define start_offset    r11

%define unused_lanes    rbx

%define job_rax         rax
%define len             rax

%define lane            rbp
%define tmp3            rbp

%define tmp             r9

%define lane_data       r10

; STACK_SPACE needs to be an odd multiple of 8
%define STACK_SPACE	8*8 + 16*10 + 8

; JOB* sha1_mb_mgr_submit_avx2(MB_MGR *state, JOB_SHA1 *job)
; arg 1 : rcx : state
; arg 2 : rdx : job
global sha1_mb_mgr_submit_avx2:function
sha1_mb_mgr_submit_avx2:

	sub     rsp, STACK_SPACE
	mov     [rsp + 8*0], rbx
	mov     [rsp + 8*3], rbp
	mov     [rsp + 8*4], r12
	mov     [rsp + 8*5], r13
	mov     [rsp + 8*6], r14
	mov     [rsp + 8*7], r15
%ifidn __OUTPUT_FORMAT__, win64
	mov     [rsp + 8*1], rsi
	mov     [rsp + 8*2], rdi
	vmovdqa  [rsp + 8*8 + 16*0], xmm6
	vmovdqa  [rsp + 8*8 + 16*1], xmm7
	vmovdqa  [rsp + 8*8 + 16*2], xmm8
	vmovdqa  [rsp + 8*8 + 16*3], xmm9
	vmovdqa  [rsp + 8*8 + 16*4], xmm10
	vmovdqa  [rsp + 8*8 + 16*5], xmm11
	vmovdqa  [rsp + 8*8 + 16*6], xmm12
	vmovdqa  [rsp + 8*8 + 16*7], xmm13
	vmovdqa  [rsp + 8*8 + 16*8], xmm14
	vmovdqa  [rsp + 8*8 + 16*9], xmm15
%endif

	mov	DWORD(tmp2), _unused_lanes
	add	tmp2, state 	; tmp2= state + _unused_lanes
	mov	unused_lanes, [tmp2]
	mov	DWORD(lane), DWORD(unused_lanes)
	and	DWORD(lane), 0xF
	shr	unused_lanes, 4
	mov	dword [job + _status], STS_BEING_PROCESSED
	lea	lane_data, [state + lane*8]
	mov	[tmp2], unused_lanes
	mov	DWORD(len), [job + _len]

	mov	[lane_data + _job_in_lane + _ldata ], job

	shl	DWORD(len),4
	or	DWORD(len), DWORD(lane)
	lea	p, [state + 4*lane]
	mov	[p + _lens], DWORD(len)
	; Load digest words from result_digest
	; p isn't
	vmovdqu	xmm0, [job + _result_digest + 0*16]
	mov	DWORD(tmp), [job + _result_digest + 1*16]

	vmovd   [p + 0*32], xmm0
	vpextrd [p + 1*32], xmm0, 1
	vpextrd [p + 2*32], xmm0, 2
	vpextrd [p + 3*32], xmm0, 3
	mov     [p + 4*32], DWORD(tmp)
	mov	p, [job + _buffer]
	mov	[lane_data + _args_data_ptr ], p

	add	dword [state + _num_lanes_inuse], 1
	cmp	DWORD(unused_lanes), 0xf
	jne	return_null

start_loop:
	; Find min length
	lea	rax,  [state +_lens]
	vmovdqu ymm0, [rax + 0*16]
	vextracti128 xmm1, ymm0, 0x1
	vpminud xmm2, xmm0, xmm1        ; xmm2 has {D,C,B,A}
	vpalignr xmm3, xmm3, xmm2, 8    ; xmm3 has {x,x,D,C}
	vpminud xmm2, xmm2, xmm3        ; xmm2 has {x,x,E,F}
	vpalignr xmm3, xmm3, xmm2, 4    ; xmm3 has {x,x,x,E}
	vpminud xmm2, xmm2, xmm3        ; xmm2 has min value in low dword
	vpcmpeqd xmm3, xmm3, xmm3
	vpslld	xmm3, xmm3, 0x4		; mask to clear low nibble
	vmovd   DWORD(idx), xmm2
	mov	DWORD(len2), DWORD(idx)
	and	DWORD(idx), 0xF
	shr	DWORD(len2), 4
	jz	len_is_0

	vpand   xmm2, xmm2, xmm3
	vpbroadcastd ymm2, xmm2

	vpsubd  ymm0, ymm0, ymm2

	vmovdqu [rax + 0*16], ymm0


	; "state" and "args" are the same address, arg1
	; len is arg2
	call	sha1_mb_x8_avx2

	; state and idx are intact

len_is_0:
	; process completed job "idx"
	lea	lane_data, [state + idx*8]
	add	lane_data, _ldata + _job_in_lane
	mov	DWORD(tmp2), _unused_lanes
	add	tmp2, state
	xor	DWORD(tmp3), DWORD(tmp3)
	mov	job_rax, [lane_data]
	mov	unused_lanes, [tmp2]
	mov	qword [lane_data], tmp3
	mov	BYTE(tmp3), STS_COMPLETED
	mov	dword [job_rax + _status], DWORD(tmp3)
	shl	unused_lanes, 4
	or	unused_lanes, idx
	mov	[tmp2], unused_lanes
	sub     dword [state + _num_lanes_inuse], 1
	lea	tmp2, [state + _args_digest + 4*idx ]

	vmovd	xmm0, [tmp2 + 0*32]
	vpinsrd	xmm0, [tmp2 + 1*32], 1
	vpinsrd	xmm0, [tmp2 + 2*32], 2
	vpinsrd	xmm0, [tmp2 + 3*32], 3
	mov	DWORD(tmp),  [tmp2 + 4*32]

	vmovdqa	[job_rax + _result_digest + 0*16], xmm0
	mov	[job_rax + _result_digest + 1*16], DWORD(tmp)

return:

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqa  xmm6, [rsp + 8*8 + 16*0]
	vmovdqa  xmm7, [rsp + 8*8 + 16*1]
	vmovdqa  xmm8, [rsp + 8*8 + 16*2]
	vmovdqa  xmm9, [rsp + 8*8 + 16*3]
	vmovdqa  xmm10, [rsp + 8*8 + 16*4]
	vmovdqa  xmm11, [rsp + 8*8 + 16*5]
	vmovdqa  xmm12, [rsp + 8*8 + 16*6]
	vmovdqa  xmm13, [rsp + 8*8 + 16*7]
	vmovdqa  xmm14, [rsp + 8*8 + 16*8]
	vmovdqa  xmm15, [rsp + 8*8 + 16*9]
	mov     rsi, [rsp + 8*1]
	mov     rdi, [rsp + 8*2]
%endif
	mov     rbx, [rsp + 8*0]
	mov     rbp, [rsp + 8*3]
	mov     r12, [rsp + 8*4]
	mov     r13, [rsp + 8*5]
	mov     r14, [rsp + 8*6]
	mov     r15, [rsp + 8*7]
	add     rsp, STACK_SPACE

	ret

return_null:
	xor	DWORD(job_rax), DWORD(job_rax)
	jmp	return
