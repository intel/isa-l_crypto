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
%include "sha1_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

extern sha1_mb_x8_avx2
extern sha1_opt_x1

default rel

%ifidn __OUTPUT_FORMAT__, elf64
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; LINUX register definitions
%define arg1    rdi ; rcx
%define arg2    rsi ; rdx

%define tmp4    rdx
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%else

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; WINDOWS register definitions
%define arg1    rcx
%define arg2    rdx

%define tmp4    rsi
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%endif

; Common register definitions

%define state   arg1
%define job     arg2
%define len2    arg2

; idx must be a register not clobberred by sha1_mb_x8_avx2 and sha1_opt_x1
%define idx             rbp

%define unused_lanes    rbx
%define lane_data       rbx
%define tmp2            rbx

%define job_rax         rax
%define tmp1            rax
%define size_offset     rax
%define tmp             rax
%define start_offset    rax

%define tmp3            arg1

%define extra_blocks    arg2
%define p               arg2


; STACK_SPACE needs to be an odd multiple of 8
_XMM_SAVE_SIZE  equ 10*16
_GPR_SAVE_SIZE  equ 8*8
_ALIGN_SIZE     equ 8

_XMM_SAVE       equ 0
_GPR_SAVE       equ _XMM_SAVE + _XMM_SAVE_SIZE
STACK_SPACE     equ _GPR_SAVE + _GPR_SAVE_SIZE + _ALIGN_SIZE

%define APPEND(a,b) a %+ b

; SHA1_JOB* sha1_mb_mgr_flush_avx2(SHA1_MB_JOB_MGR *state)
; arg 1 : rcx : state
global sha1_mb_mgr_flush_avx2:function
sha1_mb_mgr_flush_avx2:
	sub     rsp, STACK_SPACE
	mov     [rsp + _GPR_SAVE + 8*0], rbx
	mov     [rsp + _GPR_SAVE + 8*3], rbp
	mov     [rsp + _GPR_SAVE + 8*4], r12
	mov     [rsp + _GPR_SAVE + 8*5], r13
	mov     [rsp + _GPR_SAVE + 8*6], r14
	mov     [rsp + _GPR_SAVE + 8*7], r15
%ifidn __OUTPUT_FORMAT__, win64
	mov     [rsp + _GPR_SAVE + 8*1], rsi
	mov     [rsp + _GPR_SAVE + 8*2], rdi
	vmovdqa  [rsp + _XMM_SAVE + 16*0], xmm6
	vmovdqa  [rsp + _XMM_SAVE + 16*1], xmm7
	vmovdqa  [rsp + _XMM_SAVE + 16*2], xmm8
	vmovdqa  [rsp + _XMM_SAVE + 16*3], xmm9
	vmovdqa  [rsp + _XMM_SAVE + 16*4], xmm10
	vmovdqa  [rsp + _XMM_SAVE + 16*5], xmm11
	vmovdqa  [rsp + _XMM_SAVE + 16*6], xmm12
	vmovdqa  [rsp + _XMM_SAVE + 16*7], xmm13
	vmovdqa  [rsp + _XMM_SAVE + 16*8], xmm14
	vmovdqa  [rsp + _XMM_SAVE + 16*9], xmm15
%endif

	; use num_lanes_inuse to judge all lanes are empty
	
	lea     tmp, [state+  _ldata + 1 * _LANE_DATA_size + _job_in_lane]
        xor     DWORD(idx), DWORD(idx)
        cmp     DWORD(idx), dword [tmp + _num_lanes_inuse -(_ldata + 1 * _LANE_DATA_size + _job_in_lane)] ; idx=zero. offset from tmp
        jz      return_null


	vpxor   xmm0, xmm0,xmm0
        vpcmpeqq ymm1,ymm0,[tmp]
        vpcmpeqq ymm2,ymm0,[tmp+4*_LANE_DATA_size +_job_in_lane]
        vpmovmskb DWORD(tmp), ymm2 ; high cmp mask
        vpmovmskb DWORD(idx), ymm1 ; low cmp mask
        shl     tmp, 32
        or      idx, tmp
        not     idx
        tzcnt   idx, idx
        shr     DWORD(idx), 3 ; divide by 8
        add     DWORD(idx), 1 ;

copy_lane_data:
	lea     tmp, [state + 8*idx]
	mov	ebp, _args + _data_ptr
        or      DWORD(tmp4), -1 ; 0xFFFFFFFF
	
	vpbroadcastq ymm1, [tmp+rbp]; broadcast tmp
        
        lea     r9, [state+ _ldata+ _job_in_lane]
	mov	r15, rbp  ; offset from state = _args + _data_ptr
        add     r15,state
        mov     ebx, _lens - (_args + _data_ptr)
        add     rbx, r15
	vpcmpeqq ymm2, ymm0, [r9]	; 4 lanes, mask for qwords
	vmovdqu ymm3, [r15]
	vpmovmskb	eax, ymm2 	;low mask
	vpblendvb ymm3, ymm3, ymm1, ymm2 ; 
	vpcmpeqq ymm4, ymm0, [r9 + 4 * _LANE_DATA_size]	; 4 lanes, mask for qwords
	vpmovmskb	ebp, ymm4	; high mask
	vmovdqu [r15], ymm3
	vmovdqu ymm3, [r15+0x20]
	vpblendvb ymm3, ymm3, ymm1, ymm4 ; 
	vmovdqu [r15+0x20], ymm3
	shl	rbp, 32
	or	rax, rbp ; merge the mask

%assign I 0
%rep 4
        mov     ebp, [rbx + 4*I]
        test	al, 1	;  check the LSB of mask
	cmovnz	ebp, DWORD(tmp4)	
	shr	rax,8
        mov     dword [rbx + 4*I], ebp

%assign I (I+1)
%endrep

	; after 4 iteration we don't need REX prefix anymore
%assign I 4
%rep 4
        mov     ebp, [rbx + 4*I]
        test	al, 1	;  check the LSB of mask
	cmovnz	ebp, DWORD(tmp4)	
	shr	eax,8
        mov     dword [rbx + 4*I], ebp
%assign I (I+1)
%endrep

	; Find min length
	vmovdqu ymm0, [state + _lens + 0*16]
	vextracti128 xmm1, ymm0, 0x1
	vpminud xmm2, xmm0, xmm1        ; xmm2 has {D,C,B,A}
	vpalignr xmm3, xmm3, xmm2, 8    ; xmm3 has {x,x,D,C}
	vpminud xmm2, xmm2, xmm3        ; xmm2 has {x,x,E,F}
	vpalignr xmm3, xmm3, xmm2, 4    ; xmm3 has {x,x,x,E}
	vpminud xmm2, xmm2, xmm3        ; xmm2 has min value in low dword

	vmovd   DWORD(idx), xmm2
	mov	DWORD(len2), DWORD(idx)
	and	DWORD(idx), 0xF
	shr	DWORD(len2), 4
	test	DWORD(len2), DWORD(len2)
	jz	len_is_0

	vpcmpeqd xmm3,xmm3,xmm3		; prepare mask to clean low nibble
	vpslld  xmm3,xmm3, 4

	; compare with sha-sb threshold, if num_lanes_inuse <= threshold, using sb func
	cmp	dword [state + _num_lanes_inuse], SHA1_SB_THRESHOLD_AVX2
	ja	mb_processing

	; lensN-len2=idx
	mov     [state + _lens + idx*4], DWORD(idx)
	mov	r10, idx
	or	r10, 0x2000	; avx2 has 8 lanes *4, r10b is idx, r10b2 is 32
	; "state" and "args" are the same address, arg1
	; len is arg2, idx and nlane in r10
	call    sha1_opt_x1
	; state and idx are intact
	jmp	len_is_0

mb_processing:
	vpand   xmm2, xmm2,xmm3
	vpbroadcastd ymm2, xmm2

	vpsubd  ymm0, ymm0, ymm2

	vmovdqu [state + _lens + 0*16], ymm0



	; "state" and "args" are the same address, arg1
	; len is arg2
	call	sha1_mb_x8_avx2
	; state and idx are intact

len_is_0:
	; process completed job "idx"
	lea	lane_data, [state + idx*8]
	xor	DWORD(tmp4),DWORD(tmp4)
	add	lane_data, _ldata + _job_in_lane
	mov	job_rax, [lane_data]
	mov	qword [lane_data], tmp4		; tmp4 is zero
	mov	BYTE(tmp4), STS_COMPLETED
	mov	dword [job_rax + _status], DWORD(tmp4)
	mov	DWORD(tmp4), _unused_lanes
	add	tmp4, state
	mov	unused_lanes, [tmp4]
	shl	unused_lanes, 4
	or	unused_lanes, idx
	mov	[tmp4], unused_lanes
	
	sub     dword [state + _num_lanes_inuse], 1;  DWORD(tmp4)
	lea	tmp4, [state + _args_digest + 4*idx]
	vmovd	xmm0, [tmp4 + 0*32]
	vpinsrd	xmm0, [tmp4 + 1*32], 1
	vpinsrd	xmm0, [tmp4 + 2*32], 2
	vpinsrd	xmm0, [tmp4 + 3*32], 3
	mov	DWORD(tmp2),  [tmp4 + 4*32]

	vmovdqa	[job_rax + _result_digest + 0*16], xmm0
	mov	[job_rax + _result_digest + 1*16], DWORD(tmp2)

return:

%ifidn __OUTPUT_FORMAT__, win64
	vmovdqa  xmm6, [rsp + _XMM_SAVE + 16*0]
	vmovdqa  xmm7, [rsp + _XMM_SAVE + 16*1]
	vmovdqa  xmm8, [rsp + _XMM_SAVE + 16*2]
	vmovdqa  xmm9, [rsp + _XMM_SAVE + 16*3]
	vmovdqa  xmm10, [rsp + _XMM_SAVE + 16*4]
	vmovdqa  xmm11, [rsp + _XMM_SAVE + 16*5]
	vmovdqa  xmm12, [rsp + _XMM_SAVE + 16*6]
	vmovdqa  xmm13, [rsp + _XMM_SAVE + 16*7]
	vmovdqa  xmm14, [rsp + _XMM_SAVE + 16*8]
	vmovdqa  xmm15, [rsp + _XMM_SAVE + 16*9]
	mov     rsi, [rsp + _GPR_SAVE + 8*1]
	mov     rdi, [rsp + _GPR_SAVE + 8*2]
%endif
	mov     rbx, [rsp + _GPR_SAVE + 8*0]
	mov     rbp, [rsp + _GPR_SAVE + 8*3]
	mov     r12, [rsp + _GPR_SAVE + 8*4]
	mov     r13, [rsp + _GPR_SAVE + 8*5]
	mov     r14, [rsp + _GPR_SAVE + 8*6]
	mov     r15, [rsp + _GPR_SAVE + 8*7]
	add     rsp, STACK_SPACE

	ret

return_null:
	xor	DWORD(job_rax), DWORD(job_rax)
	jmp	return
