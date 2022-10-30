/**********************************************************************
  Copyright(c) 2022 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
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

#if defined(NO_SVE2)
	.arch armv8.2-a+sve
#else
	.arch armv8.2-a+sve2
#endif

#include "sha1_sve_common.S"

.macro load_init
.endm

.altmacro
/* load data from user input buffer (read only) */
.macro load_init_word	pipelines:req,index:req,reg0:req,reg1
	mov	tmp,\index
	add	src,block_ptr,lane_offset,lsl #2
	add	tmp,src,tmp,lsl #6
	ld1w	{\reg0\().s}, p0/z, [tmp]
	.if \pipelines == 2
		ld1w	{\reg1\().s}, p1/z, [tmp, #1, MUL VL]
	.endif
.endm

/* write data into our cache on stack */
.macro __write_word pipelines:req,ptr:req,offset:req,idx0:req,reg0:req,idx1,reg1
	addvl	tmp,\ptr,\offset
	st1w    {\reg0\().s},p0,[tmp, \idx0, MUL VL]
	.if \pipelines == 2
		st1w    {\reg1\().s},p0,[tmp, \idx1, MUL VL]
	.endif
.endm

/* read data from cache on stack */
.macro __read_word pipelines:req,ptr:req,offset:req,idx0:req,reg0:req,idx1,reg1
	addvl	tmp,\ptr,\offset
	ld1w    {\reg0\().s},p0/z,[tmp, \idx0, MUL VL]
	.if \pipelines == 2
		ld1w    {\reg1\().s},p0/z,[tmp, \idx1, MUL VL]
	.endif
.endm

/*
 * data on stack, with consideration of cache efficiency
 * layout for two pipelines:
 *
 *  pipe0_vec0 pipe1_vec0 pipe0_vec1 pipe1_vec1 pipe0_vec2 pipe1_vec2 pipe0_vec3 pipe1_vec3
 *  pipe0_vec4 pipe1_vec4 pipe0_vec5 pipe1_vec5 pipe0_vec6 pipe1_vec6 pipe0_vec7 pipe1_vec7
 *  etc. etc.
 *
 * for one pipeline:
 * pipe0_vec0 pipe0_vec1 pipe0_vec2 pipe0_vec3 pipe0_vec4 pipe0_vec5 pipe0_vec6 pipe0_vec7
 * etc. etc.
 */
.macro save_word	pipelines:req,windex:req,reg0:req,reg1
	.if \pipelines == 1
		idx0=\windex % 8
		offset=(\windex/8)*8
		__write_word \pipelines,data_buf,%offset,%idx0,\reg0
	.endif
	.if \pipelines == 2
		idx0=\windex % 4
		idx0=idx0*2
		idx1=idx0+1
		offset=(\windex/4)*8
		__write_word \pipelines,data_buf,%offset,%idx0,\reg0,%idx1,\reg1
	.endif
.endm

.macro __load_word	pipelines:req,windex:req,reg0:req,reg1
	.if \pipelines == 1
		idx0=\windex % 8
		offset=(\windex/8)*8
		__read_word \pipelines,data_buf,%offset,%idx0,\reg0
	.endif
	.if \pipelines == 2
		idx0=\windex % 4
		idx0=idx0*2
		idx1=idx0+1
		offset=(\windex/4)*8
		__read_word \pipelines,data_buf,%offset,%idx0,\reg0,%idx1,\reg1
	.endif
.endm

.macro load_word	pipelines:req,idx0:req,idx1:req,idx2:req,idx3:req,reg0:req,reg1:req,reg2:req,reg3:req,reg0x,reg1x,reg2x,reg3x
	__load_word	\pipelines,\idx0,\reg0,\reg0x
	__load_word	\pipelines,\idx1,\reg1,\reg1x
	__load_word	\pipelines,\idx2,\reg2,\reg2x
	__load_word	\pipelines,\idx3,\reg3,\reg3x
.endm

.macro load_abcde	pipelines:req,a0:req,b0:req,c0:req,d0:req,e0:req,a1,b1,c1,d1,e1
	add	tmp, sha1_digest, lane_offset, lsl #2
	ld1w    {\a0\().s},p0/z,[tmp]
	.if \pipelines == 2
		ld1w    {\a1\().s},p1/z,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	ld1w    {\b0\().s},p0/z,[tmp]
	.if \pipelines == 2
		ld1w    {\b1\().s},p1/z,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	ld1w    {\c0\().s},p0/z,[tmp]
	.if \pipelines == 2
		ld1w    {\c1\().s},p1/z,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	ld1w    {\d0\().s},p0/z,[tmp]
	.if \pipelines == 2
		ld1w    {\d1\().s},p1/z,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	ld1w    {\e0\().s},p0/z,[tmp]
	.if \pipelines == 2
		ld1w    {\e1\().s},p1/z,[tmp, #1, MUL VL]
	.endif
.endm

.macro save_abcde	pipelines:req,a0:req,b0:req,c0:req,d0:req,e0:req,a1,b1,c1,d1,e1
	add	tmp, sha1_digest, lane_offset, lsl #2
	st1w    {\a0\().s},p0,[tmp]
	.if \pipelines == 2
		st1w    {\a1\().s},p1,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	st1w    {\b0\().s},p0,[tmp]
	.if \pipelines == 2
		st1w    {\b1\().s},p1,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	st1w    {\c0\().s},p0,[tmp]
	.if \pipelines == 2
		st1w    {\c1\().s},p1,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	st1w    {\d0\().s},p0,[tmp]
	.if \pipelines == 2
		st1w    {\d1\().s},p1,[tmp, #1, MUL VL]
	.endif
	add	tmp, tmp, 64
	st1w    {\e0\().s},p0,[tmp]
	.if \pipelines == 2
		st1w    {\e1\().s},p1,[tmp, #1, MUL VL]
	.endif
.endm

/*
 * void mh_sha1_block_sve (const uint8_t * input_data,
 *                           uint32_t mh_sha1_digests[SHA1_DIGEST_WORDS][HASH_SEGS],
 *                           uint8_t frame_buffer[MH_SHA1_BLOCK_SIZE],
 *                           uint32_t num_blocks);
 * arg 0 pointer to input data
 * arg 1 pointer to digests, include segments digests(uint32_t digests[16][5])
 * arg 2 pointer to aligned_frame_buffer which is used to save the big_endian data.
 * arg 3 number  of 1KB blocks
 */
	input_data	.req	x0
	sha1_digest	.req	x1
	frame_buffer	.req	x2
	num_blocks	.req	w3
	src	.req	x4
	lane_offset	.req	x5
	tmp	.req	x6
	tmpw	.req	w6
	ctr	.req	w7
	total_lanes	.req	x8
	sha1key_adr	.req	x9
	data_buf	.req	x10
	savedsp		.req	x11
	veclen		.req	x12
	block_ptr	.req	x13

.macro IMPLEMENT_MH_SHA1 sve2_flag:req
	cbz	num_blocks,.return\sve2_flag\()
	sha1_sve_save_stack
	mov	total_lanes, #16
	mov	savedsp,sp

	cntw	tmp, ALL, MUL #2
	cmp	tmp, total_lanes
	b.le	1f
	cntw	tmp
1:
	lsl 	tmp, tmp, #6
	sub	data_buf,sp, tmp
	// align buffer with cache line
	and	data_buf,data_buf,#-64
	mov	sp,data_buf
	mov	lane_offset,0
	adr	sha1key_adr, SHA1KEY
.seg_loops\sve2_flag\():
	mov	block_ptr,input_data
	mov	ctr,num_blocks
	mov	tmp,lane_offset
	whilelo	p0.s, tmp, total_lanes
	incw	tmp
	cmp	tmp,total_lanes
	b.ge	.handle_1x\sve2_flag\()
	whilelo	p1.s, tmp, total_lanes
	load_abcde	2,VA_0,VB_0,VC_0,VD_0,VE_0,VA_1,VB_1,VC_1,VD_1,VE_1
10:
	sha1_single	2,\sve2_flag
	add	block_ptr,block_ptr,1024
	subs	ctr, ctr, 1
	bne	10b
	incw	lane_offset,ALL,MUL #2
	cmp	lane_offset,total_lanes
	b.lt	.seg_loops\sve2_flag\()
	b	20f
.handle_1x\sve2_flag\():
	load_abcde	1,VA_0,VB_0,VC_0,VD_0,VE_0
10:
	sha1_single	1,\sve2_flag
	add	block_ptr,block_ptr,1024
	subs	ctr, ctr, 1
	bne	10b
20:
	mov	sp,savedsp
	sha1_sve_restore_stack
.return\sve2_flag\():
	ret
.endm

	.global mh_sha1_block_sve
	.type mh_sha1_block_sve, %function
mh_sha1_block_sve:
.sve_entry:
	IMPLEMENT_MH_SHA1 0
	.size mh_sha1_block_sve, .-mh_sha1_block_sve

	.global mh_sha1_block_sve2
	.type mh_sha1_block_sve2, %function
mh_sha1_block_sve2:
#if	!defined(NO_SVE2)
	IMPLEMENT_MH_SHA1 1
#else
#warning "SVE2 has been bypassed in the build"
	b	.sve_entry
#endif
	.size mh_sha1_block_sve2, .-mh_sha1_block_sve2
