/**********************************************************************
  Copyright(c) 2022 Linaro Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Linaro Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

	.arch armv8.2-a+sve

.macro xxh32_sve_save_stack
	stp	x29, x30, [sp, -144]!
	stp	x27, x28, [sp, 16]
	stp	x25, x26, [sp, 32]
	stp	x23, x24, [sp, 48]
	stp	x21, x22, [sp, 64]
	stp	x19, x20, [sp, 80]
	stp	x17, x18, [sp, 96]
	stp	x15, x16, [sp, 112]
	stp	x13, x14, [sp, 128]
	mov	x29, sp
.endm

.macro xxh32_sve_restore_stack
	mov	sp, x29
	ldp	x27, x28, [sp, 16]
	ldp	x25, x26, [sp, 32]
	ldp	x23, x24, [sp, 48]
	ldp	x21, x22, [sp, 64]
	ldp	x19, x20, [sp, 80]
	ldp	x17, x18, [sp, 96]
	ldp	x15, x16, [sp, 112]
	ldp	x13, x14, [sp, 128]
	ldp	x29, x30, [sp], #144
.endm

// The step of seed is 16-byte.
.macro xxh32_init_seed_index idx:req, t:req
	mov	\t, 16
	index	\idx\().s, #0, \t
.endm

// The step of data is 256-byte. And the index is for the temporary buffer.
.macro xxh32_init_data_index idx:req, t:req
	mov	\t, 256
	index	\idx\().s, #0, \t
.endm

// Use address as index.
// m_addr_w is the lower part of m_addr.
.macro xxh32_init_sparse_index idx:req, job_vec:req, job_cnt:req, buffer:req, src:req, dst:req, m_addr:req, m_addr_w:req, cnt:req
	mov	\src, \job_vec
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
	mov	x12, 0
100:
	// m_addr: ranges from jobs[0], jobs[1], ...
	ldr	\m_addr, [\src], #8
	// m_addr: jobs[i].buffer, ranges from 0, ...
	ldr	\m_addr, [\m_addr]
	// m_addr_w: the low 32-bit is used as index
	str	\m_addr_w, [\dst], #4
	subs	\cnt, \cnt, 1
	bne	100b
	ld1w	\idx\().s, p0/z, [\buffer]
	mov	\dst, \buffer
	// clear the low 32-bit
	and	\m_addr, \m_addr, 0xffffffff00000000
	ldp	w13, w14, [\dst], 8
	ldp	w15, w16, [\dst], 8
	ldp	w17, w18, [\dst], 8
	ldp	w19, w20, [\dst], 8
	ldp	w21, w22, [\dst], 8
	ldp	w23, w24, [\dst], 8
	ldp	w25, w26, [\dst], 8
	ldp	w27, w28, [\dst], 8
	mov	\cnt, \job_cnt
	add	x13, x13, \m_addr
	prfm	pldl1strm, [x13, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x14, x14, \m_addr
	prfm	pldl1strm, [x14, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x15, x15, \m_addr
	prfm	pldl1strm, [x15, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x16, x16, \m_addr
	prfm	pldl1strm, [x16, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x17, x17, \m_addr
	prfm	pldl1strm, [x17, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x18, x18, \m_addr
	prfm	pldl1strm, [x18, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x19, x19, \m_addr
	prfm	pldl1strm, [x19, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x20, x20, \m_addr
	prfm	pldl1strm, [x20, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x21, x21, \m_addr
	prfm	pldl1strm, [x21, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x22, x22, \m_addr
	prfm	pldl1strm, [x22, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x23, x23, \m_addr
	prfm	pldl1strm, [x23, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x24, x24, \m_addr
	prfm	pldl1strm, [x24, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x25, x25, \m_addr
	prfm	pldl1strm, [x25, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x26, x26, \m_addr
	prfm	pldl1strm, [x26, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x27, x27, \m_addr
	prfm	pldl1strm, [x27, 512]
	subs	\cnt, \cnt, 1
	beq	105f
	add	x28, x28, \m_addr
	prfm	pldl1strm, [x28, 512]
105:
	nop
.endm

// rotate left
// Accessed Predicate registers: p0
// Accessed 8 Z registers
.macro xxh32_rtl_x4 v1:req, v2:req, v3:req, v4:req, t1:req, t2:req, t3:req, t4:req, bits:req
	lsl	\t1\().s, \v1\().s, \bits
	lsl	\t2\().s, \v2\().s, \bits
	lsl	\t3\().s, \v3\().s, \bits
	lsl	\t4\().s, \v4\().s, \bits
	lsr	\v1\().s, p0/m, \v1\().s, 32 - \bits
	lsr	\v2\().s, p0/m, \v2\().s, 32 - \bits
	lsr	\v3\().s, p0/m, \v3\().s, 32 - \bits
	lsr	\v4\().s, p0/m, \v4\().s, 32 - \bits
	orr	\v1\().s, p0/m, \v1\().s, \t1\().s
	orr	\v2\().s, p0/m, \v2\().s, \t2\().s
	orr	\v3\().s, p0/m, \v3\().s, \t3\().s
	orr	\v4\().s, p0/m, \v4\().s, \t4\().s
.endm

// round
// Accessed Predicate register: p0
// Accessed 10 Z registers
.macro xxh32_round_x4 v1:req, v2:req, v3:req, v4:req, in1:req, in2:req, in3:req, in4:req, prm1:req, prm2:req
	// seed += in * PRIM32_2;
	mla	\v1\().s, p0/m, \in1\().s, \prm2\().s
	mla	\v2\().s, p0/m, \in2\().s, \prm2\().s
	mla	\v3\().s, p0/m, \in3\().s, \prm2\().s
	mla	\v4\().s, p0/m, \in4\().s, \prm2\().s
	xxh32_rtl_x4	\v1, \v2, \v3, \v4, \in1, \in2, \in3, \in4, 13
	// seed *= PRIME32_1
	mul	\v1\().s, p0/m, \v1\().s, \prm1\().s
	mul	\v2\().s, p0/m, \v2\().s, \prm1\().s
	mul	\v3\().s, p0/m, \v3\().s, \prm1\().s
	mul	\v4\().s, p0/m, \v4\().s, \prm1\().s
.endm

// Allocate two memory blocks. One is for seed buffer, and the other is for
// data buffer.
// Param job_vec is read-only in the macro.
// Param seed_buf, data_buf, tmp are updated in the macro.
.macro xxh32_alloc_on_stack job_cnt:req, seed_buf:req, data_buf:req, tmp:req
	// Reserve the unified seed buffer for all data lanes.
	// Each lane costs 16-byte long.
	lsl	\tmp, \job_cnt, 4
	sub	\seed_buf, sp, \tmp
	// Reserve the unified data buffer for all data lanes.
	// Each lane costs 256-byte long.
	lsl	\tmp, \job_cnt, 8
	sub	\data_buf, \seed_buf, \tmp
	//sub	\data_buf, \data_buf, \tmp
	mov	sp, \data_buf
.endm

// Load seed from jobs into a single memory block
// Param job_vec, job_cnt, buffer are read-only in the macro.
// Param src, dst, tmp and cnt are updated in the macro.
.macro xxh32_load_seed_from_jobs job_vec:req, job_cnt:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \job_vec
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
110:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[i].digest, ranges from 0, ...
	add	\tmp, \tmp, #16
	// Read 128-bit seed value
	ld1	{v7.16b}, [\tmp]
	// Save 128-bit seed value in the continous buffer
	st1	{v7.16b}, [\dst], #16
	subs	\cnt, \cnt, #1
	bne	110b
.endm

// Load data from jobs into a single memory block
.macro xxh32_load_data_from_jobs job_vec:req, job_cnt:req, block_idx:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \job_vec
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
120:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[i].buffer, ranges from 0, ...
	ldr	\tmp, [\tmp]
	// tmp: block address in job[i].buffer (offset: 256-byte)
	add	\tmp, \tmp, \block_idx, lsl #8
	mov	x13, #256
123:
	ld1	{v7.16b}, [\tmp], 16
	st1	{v7.16b}, [\dst], 16
	subs	x13, x13, 16
	bne	123b
	subs	\cnt, \cnt, 1
	bne	120b
	prfm	pldl1strm, [\tmp, #512]
.endm

.macro xxh32_save_seed_to_jobs job_vec:req, job_cnt, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \buffer
	mov	\dst, \job_vec
	mov	\cnt, \job_cnt
130:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\dst], 8
	// tmp: jobs[i].digest, ranges from 0, ...
	add	\tmp, \tmp, 16
	ld1	{v7.16b}, [\src], 16
	st1	{v7.16b}, [\tmp]
	subs	\cnt, \cnt, 1
	bne	130b
.endm

// Load sparse seed or data from a single memory block into vector registers.
// Param buf and idx are read-only in the macro.
// Param tmp, in1, in2, in3, in4 are updated in the macro.
// Accessed predicate registers: p0
.macro xxh32_sparse_load buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
	mov	\tmp, \buf
	ld1w	\in1\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	ld1w	\in2\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	ld1w	\in3\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	ld1w	\in4\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
.endm

// Save sparse seed or data from vector registers to a single memory block.
// Param buf, idx, in1, in2, in3, in4 are read-only in the macro.
// Param tmp is updated in the macro.
.macro xxh32_sparse_save buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
	mov	\tmp, \buf
	st1w	\in1\().s, p0, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	st1w	\in2\().s, p0, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	st1w	\in3\().s, p0, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
	st1w	\in4\().s, p0, [\tmp, \idx\().s, UXTW 0]
	add	\tmp, \tmp, #4
.endm

.macro xxh32_sparse_prefetch job_cnt:req, cnt:req
	mov	\cnt, \job_cnt
	prfm	pldl1strm, [x13, 512]
	add	x13, x13, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x14, 512]
	add	x14, x14, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x15, 512]
	add	x15, x15, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x16, 512]
	add	x16, x16, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x17, 512]
	add	x17, x17, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x18, 512]
	add	x18, x18, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x19, 512]
	add	x19, x19, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x20, 512]
	add	x20, x20, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x21, 512]
	add	x21, x21, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x22, 512]
	add	x22, x22, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x23, 512]
	add	x23, x23, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x24, 512]
	add	x24, x24, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x25, 512]
	add	x25, x25, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x26, 512]
	add	x26, x26, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x27, 512]
	add	x27, x27, 256
	subs	\cnt, \cnt, 1
	beq	140f
	prfm	pldl1strm, [x28, 512]
	add	x28, x28, 256
140:
	nop
.endm

// Compute seed for one block data
// Param buf, prm1, prm2, didx are read-only in the macro.
// Param s1, s2, s3, s4, in1, in2, in3, in4 are updated in the macro.
.macro xxh32_single job_vec:req, job_cnt:req, blk_idx:req, buf:req, didx:req, prm1:req, prm2:req, s1:req, s2:req, s3:req, s4:req, in1:req, in2:req, in3:req, in4:req, src:req, dst:req, tmp:req, cnt:req
	cbz	x3, 154f
	// x3 == 1, means more than one 4GB slot is used. Memory copy should
	// be used to format a traverse matrix.
	xxh32_load_data_from_jobs	\job_vec, \job_cnt, \blk_idx, \buf, \src, \dst, \tmp, \cnt
	mov	\cnt, #16
	mov	\dst, \buf
150:
	// load data
	xxh32_sparse_load	\dst, \didx, \in1, \in2, \in3, \in4, \tmp
	mov	\dst, \tmp
	xxh32_round_x4	\s1, \s2, \s3, \s4, \in1, \in2, \in3, \in4, \prm1, \prm2
	subs	\cnt, \cnt, #1
	bne	150b
	b	158f
154:
	mov	\cnt, 16
155:
	// TODO: replace x9 by an input parameter
	xxh32_sparse_load	x9, \didx, \in1, \in2, \in3, \in4, \tmp
	mov	x9, \tmp
	xxh32_round_x4	\s1, \s2, \s3, \s4, \in1, \in2, \in3, \in4, \prm1, \prm2
	subs	\cnt, \cnt, #1
	bne	155b
	xxh32_sparse_prefetch	\job_cnt, \cnt
158:
	nop
.endm


.macro xxh64_sve_save_stack
	stp	x29, x30, [sp, -32]!
	mov	x29, sp
.endm

.macro xxh64_sve_restore_stack
	mov	sp, x29
	ldp	x29, x30, [sp], #32
.endm

.macro xxh64_init_seed_index idx:req, tmp:req
	// Each seed is 64-bit (8-byte) long. There're 4 seeds for one lane.
	// 8 * 4 = 32
	mov	\tmp, 32
	index	\idx\().d, #0, \tmp
.endm

.macro xxh64_init_data_index idx:req, tmp:req
	// Data length is 256-byte long.
	mov	\tmp, 256
	index	\idx\().d, #0, \tmp
.endm

// Use address as index.
.macro xxh64_init_sparse_index idx:req, job_vec:req, job_cnt:req, buffer:req, src:req, dst:req, m_addr:req, cnt:req
	mov	\src, \job_vec
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
300:
	// m_addr: ranges from jobs[0], jobs[1], ...
	ldr	\m_addr, [\src], #8
	// m_addr: jobs[i].buffer, ranges from 0, ...
	ldr	\m_addr, [\m_addr]
	str	\m_addr, [\dst], #8
	subs	\cnt, \cnt, 1
	bne	300b
	ld1d	\idx\().d, p0/z, [\buffer]
.endm

// rotate left
// Accessed Predicate registers: p0
// Accessed 8 Z registers
.macro xxh64_rtl_x4 v1:req, v2:req, v3:req, v4:req, t1:req, t2:req, t3:req, t4:req, bits:req
	lsl	\t1\().d, \v1\().d, \bits
	lsl	\t2\().d, \v2\().d, \bits
	lsl	\t3\().d, \v3\().d, \bits
	lsl	\t4\().d, \v4\().d, \bits
	lsr	\v1\().d, p0/m, \v1\().d, 64 - \bits
	lsr	\v2\().d, p0/m, \v2\().d, 64 - \bits
	lsr	\v3\().d, p0/m, \v3\().d, 64 - \bits
	lsr	\v4\().d, p0/m, \v4\().d, 64 - \bits
	orr	\v1\().d, p0/m, \v1\().d, \t1\().d
	orr	\v2\().d, p0/m, \v2\().d, \t2\().d
	orr	\v3\().d, p0/m, \v3\().d, \t3\().d
	orr	\v4\().d, p0/m, \v4\().d, \t4\().d
.endm

// round
// Accessed Predicate register: p0
// Accessed 10 Z registers
.macro xxh64_round_x4 v1:req, v2:req, v3:req, v4:req, in1:req, in2:req, in3:req, in4:req, prm1:req, prm2:req
	// seed += in * PRIM64_2;
	mla	\v1\().d, p0/m, \in1\().d, \prm2\().d
	mla	\v2\().d, p0/m, \in2\().d, \prm2\().d
	mla	\v3\().d, p0/m, \in3\().d, \prm2\().d
	mla	\v4\().d, p0/m, \in4\().d, \prm2\().d
	xxh64_rtl_x4	\v1, \v2, \v3, \v4, \in1, \in2, \in3, \in4, 31
	// seed *= PRIME64_1
	mul	\v1\().d, p0/m, \v1\().d, \prm1\().d
	mul	\v2\().d, p0/m, \v2\().d, \prm1\().d
	mul	\v3\().d, p0/m, \v3\().d, \prm1\().d
	mul	\v4\().d, p0/m, \v4\().d, \prm1\().d
.endm

// Create both seed and data buf on stack
.macro xxh64_create_stack_buf job_cnt:req, seed_buf:req, data_buf:req, tmp:req
	// Reserve the unified seed buffer for all data lanes.
	// Each lane costs 32-byte (64 * 4) long.
	mov	\tmp, \job_cnt, lsl #5
	sub	\seed_buf, sp, \tmp
	// Reserve the unified data buffer for all data lanes.
	// Each lane costs 256-byte long.
	mov	\tmp, \job_cnt, lsl #8
	sub	\data_buf, \seed_buf, \tmp
	mov	sp, \data_buf
.endm

// src, dst, tmp: all temporary registers
// Load seeds from different jobs, and save them in one continuous buffer.
.macro xxh64_load_seed_from_jobs jobs:req, job_cnt:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \jobs
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
101:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[1].digest, ranges from 0, ...
	// 16 is the offset of digest field
	add	\tmp, \tmp, #16
	// Read 256-bit seed value (64 * 4)
	ld1	{v7.16b}, [\tmp], 16
	ld1	{v8.16b}, [\tmp]
	// Save 256-bit seed value in the continous buffer
	st1	{v7.16b}, [\dst], 16
	st1	{v8.16b}, [\dst], 16
	subs	\cnt, \cnt, #1
	bne	101b
.endm

/*
 * IN: jobs, job_cnt, buffer, block_idx
 * OUT: src, dst, tmp, cnt, t1, t2, t3, t4
 */
.macro xxh64_load_data_from_jobs jobs:req, job_cnt:req, blk_idx:req, buf:req, src:req, dst:req, tmp:req, cnt:req/*, t1:req, t2:req, t3:req, t4:req */
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \jobs
	mov	\dst, \buf
	mov	\cnt, \job_cnt
102:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[i].buffer, ranges from 0, ...
	ldr	\tmp, [\tmp]
	// tmp: block address in job[i].buffer (offset: 256-byte)
	add	\tmp, \tmp, \blk_idx, lsl #8
	// Each data lane is 256-byte long.
	mov	x13, #256
110:
	ldr	x12, [\tmp], #8
	str	x12, [\dst], #8
	subs	x13, x13, #8
	bne	110b
	subs	\cnt, \cnt, #1
	bne	102b
.endm

// Load sparse seed or data from a single memory block into vector registers.
// Param buf and idx are read-only in the macro.
// Param tmp, in1, in2, in3, in4 are updated in the macro.
// Accessed predicate registers: p0
.macro xxh64_sparse_load buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
	mov	\tmp, \buf
	ld1d	\in1\().d, p0/z, [\tmp, \idx\().d]
	add	\tmp, \tmp, #8
	ld1d	\in2\().d, p0/z, [\tmp, \idx\().d]
	add	\tmp, \tmp, #8
	ld1d	\in3\().d, p0/z, [\tmp, \idx\().d]
	add	\tmp, \tmp, #8
	ld1d	\in4\().d, p0/z, [\tmp, \idx\().d]
	add	\tmp, \tmp, #8
.endm

// Save sparse seed or data from vector registers to a single memory block.
// Param buf, idx, in1, in2, in3, in4 are read-only in the macro.
// Param tmp is updated in the macro.
.macro xxh64_sparse_save buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
	mov	\tmp, \buf
	st1d	\in1\().d, p0, [\tmp, \idx\().d, UXTW 0]
	add	\tmp, \tmp, #8
	st1d	\in2\().d, p0, [\tmp, \idx\().d, UXTW 0]
	add	\tmp, \tmp, #8
	st1d	\in3\().d, p0, [\tmp, \idx\().d, UXTW 0]
	add	\tmp, \tmp, #8
	st1d	\in4\().d, p0, [\tmp, \idx\().d, UXTW 0]
	add	\tmp, \tmp, #8
.endm

.macro xxh64_save_seed_to_jobs job_vec:req, job_cnt:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \buffer
	mov	\dst, \job_vec
	mov	\cnt, \job_cnt
130:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\dst], 8
	// tmp: jobs[i].digest, ranges from 0, ...
	add	\tmp, \tmp, 16
	// Read 256-bit seed value (64 * 4)
	ld1	{v7.16b}, [\src], 16
	ld1	{v8.16b}, [\src], 16
	st1	{v7.16b}, [\tmp], 16
	st1	{v8.16b}, [\tmp]
	subs	\cnt, \cnt, 1
	bne	130b
.endm

.macro xxh64_single jobs:req, job_cnt:req, blk_idx:req, buf:req, didx:req, prm1:req, prm2:req, s1:req, s2:req, s3:req, s4:req, in1:req, in2:req, in3:req, in4:req, src:req, dst:req, tmp:req, cnt:req
	// Each lane loads 8 * 4 = 32 (bytes) data.
	// 256 / 32 = 8
	mov	\cnt, #8
	// dst: block address in job[i].buffer (offset: 256-byte)
	mov	\dst, \blk_idx, lsl #8
150:
	xxh64_sparse_load	\dst, \didx, \in1, \in2, \in3, \in4, \tmp
	mov	\dst, \tmp
	xxh64_round_x4	\s1, \s2, \s3, \s4, \in1, \in2, \in3, \in4, \prm1, \prm2
	subs	\cnt, \cnt, #1
	bne	150b
.endm


	.global xxh32_mb_sve_max_lanes
	.type xxh32_mb_sve_max_lanes, %function
xxh32_mb_sve_max_lanes:
	cntw	x0
	add	x0, x0, x0
	ret
	.size xxh32_mb_sve_max_lanes, .-xxh32_mb_sve_max_lanes

	.global xxh32_mb_sve
	.type xxh32_mb_sve, %function
/*
	num_blocks	.req	w0
	job_cnt		.req	w1
	job_vec		.req	x2
	src		.req	x5
	dst		.req	x6
	tmp		.req	x8
	tmpw		.req	w8
	block_ctr	.req	x9
	block_ctr_w	.req	w9
	savedsp		.req	x10
	databuf		.req	x11
	counter		.req	w12
	veclen		.req	x13
	veclen_w	.req	w13
	abcd_buf	.req	x14	// store hash value
	xxh32_prm_adr	.req	x15
	prime32_1	.req	z0
	prime32_2	.req	z1
	offset		.req	z2
	V1		.req	z3
	V2		.req	z4
	V2		.req	z5
	V3		.req	z6
	IN1		.req	z7
	IN2		.req	z8
	IN3		.req	z9
	IN4		.req	z10
*/

xxh32_mb_sve:
	xxh32_sve_save_stack
	cbz	x2, 90f

	// x4: seed_buf in stack
	// x5: data_buf in stack
	xxh32_alloc_on_stack	x1, x4, x5, x6

	// x1/w1: job_cnt
	whilelo	p0.s, wzr, w1

	adr	x8, XXH32_PRIME
	// Z0: XXH32_PRIME32_1
	ldr	x6, [x8], 4
	// Z1: XXH32_PRIME32_2
	ldr	x7, [x8]
	mov	z0.s, p0/m, w6
	mov	z1.s, p0/m, w7
	// Z2: seed index
	// Z12: data index
	xxh32_init_seed_index	z2, w6
	cbz	x3, 5f
	xxh32_init_data_index	z12, w6
	b	6f
5:
	xxh32_init_sparse_index	z12, x0, x1, x5, x7, x8, x9, w9, x10
6:
	xxh32_load_seed_from_jobs	x0, x1, x4, x7, x8, x6, x10
	// Load sparse seeds into vector registers.
	xxh32_sparse_load	x4, z2, z3, z4, z5, z6, x6

	// x11: block index
	mov	x11, #0
10:
	xxh32_single	x0, x1, x11, x5, z12, z0, z1, z3, z4, z5, z6, z7, z8, z9, z10, x7, x8, x6, x10
	add	x11, x11, #1
	cmp	x11, x2
	bne	10b

	// Save sparse seeds from vector registers to a memory block.
	xxh32_sparse_save	x4, z2, z3, z4, z5, z6, x6
	// Save sparse seeds back into job_vec.
	xxh32_save_seed_to_jobs	x0, x1, x4, x7, x8, x6, x10
90:
	xxh32_sve_restore_stack
	ret
	.size xxh32_mb_sve, .-xxh32_mb_sve


	.global xxh64_mb_sve
	.type xxh64_mb_sve, %function
xxh64_mb_sve:
	xxh64_sve_save_stack
	cbz	x2, 90f

	// x4 (updated): seed_buf in stack
	// x5 (updated): data_buf in stack
	// xxh64_create_stack_buf_01(job_cnt, seed_buf, data_buf, tmp);
	xxh64_create_stack_buf	x1, x4, x5, x6

	// w1 (RD-only): job_cnt
	whilelo	p0.d, wzr, w1
	ptrue	p1.b
	// xxh64_init_seed_index(idx, tmp);
	// Z2: index of seed
	// Z3: index of data
	xxh64_init_seed_index	z2, x6
	//xxh64_init_data_index	z3, x6
	xxh64_init_sparse_index	z3, x0, x1, x5, x7, x8, x9, x10

	xxh64_load_seed_from_jobs	x0, x1, x4, x7, x8, x6, x10
	// Load sparse seeds into vector registers [Z5 - Z8].
	xxh64_sparse_load	x4, z2, z4, z5, z6, z7, x6

	// x8: PRIME address
	adr	x8, XXH64_PRIME
	// x6 & Z0: PRIME64_01
	ldr	x6, [x8], 8
	mov	z0.d, p1/m, x6
	// x6 & Z1: PRIME64_02
	ldr	x6, [x8]
	mov	z1.d, p1/m, x6

        // x11: block index
	mov	x11, #0
10:
	xxh64_single	x0, x1, x11, x5, z3, z0, z1, z4, z5, z6, z7, z8, z9, z10, z11, x7, x8, x6, x10
	add	x11, x11, #1
	cmp	x11, x2
	bne	10b

	// Save sparse seeds from vector registers to a memory block.
	xxh64_sparse_save	x4, z2, z4, z5, z6, z7, x6
	// Save sparse seeds back into job_vec.
	xxh64_save_seed_to_jobs	x0, x1, x4, x7, x8, x6, x10

90:
	xxh64_sve_restore_stack
	ret
	.size xxh64_mb_sve, .-xxh64_mb_sve


	.section .rodata.cst16,"aM",@progbits,16
	.align 16

XXH64_PRIME:
	.dword	0x9E3779B185EBCA87	// PRIME64_1
	.dword	0xC2B2AE3D27D4EB4F	// PRIME64_2
	.dword	0x165667B19E3779F9	// PRIME64_3
	.dword	0x85EBCA77C2B2AE63	// PRIME64_4
	.dword	0x27D4EB2F165667C5	// PRIME64_5

XXH32_PRIME:
	.word	0x9E3779B1	// PRIME32_1
	.word	0x85EBCA77	// PRIME32_2
	.word	0xC2B2AE3D	// PRIME32_3
	.word	0x27D4E82F	// PRIME32_4
	.word	0x165667B1	// PRIME32_5

