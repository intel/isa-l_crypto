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
	VK	.req z0
	VA_0	.req z1
	VB_0	.req z2
	VC_0	.req z3
	VD_0	.req z4
	VE_0	.req z5
	VT_0	.req z6
	VF_0	.req z7
	TMPV0	.req z16
	TMPV1	.req z17
	TMPV2	.req z18
	TMPV3	.req z19
	TMPV4	.req z20
	TMPV0X	.req z21
	TMPV1X	.req z22
	TMPV2X	.req z23
	TMPV3X	.req z24
	TMPV4X	.req z25
	WORD3_0	.req z16
	WORD8_0	.req z17
	WORD14_0	.req z18
	WORD16_0	.req z19
	WORD_0	.req z19
	WORD3_1	.req z20
	WORD8_1	.req z21
	WORD14_1	.req z22
	WORD16_1	.req z23
	WORD_1	.req z23
	VA_1	.req z26
	VB_1	.req z27
	VC_1	.req z28
	VD_1	.req z29
	VE_1	.req z30
	VT_1	.req z31
	VF_1	.req z8
	VZERO	.req z9
	VT0_0	.req z10
	VT1_0	.req z11
	VT0_1	.req z12
	VT1_1	.req z13

	TT	.req z0

.macro rotate_left0	out:req,in:req,tmp:req,bits:req,args:vararg
	.if have_sve2 == 0
		lsl	\tmp\().s,\in\().s,\bits
	.else
		movprfx	\out,\in
		xar	\out\().s,\out\().s,VZERO.s,32-\bits
	.endif

	.ifnb	\args
		rotate_left0	\args
	.endif
.endm

.macro rotate_left1	out:req,in:req,tmp:req,bits:req,args:vararg
	.if have_sve2 == 0
		lsr	\out\().s,\in\().s,32-\bits
	.endif
	.ifnb	\args
		rotate_left1	\args
	.endif
.endm

.macro rotate_left2	out:req,in:req,tmp:req,bits:req,args:vararg
	.if have_sve2 == 0
		orr	\out\().d,\out\().d,\tmp\().d
	.endif
	.ifnb	\args
		rotate_left2	\args
	.endif
.endm

.macro rotate_left	args:vararg
	rotate_left0	\args
	rotate_left1	\args
	rotate_left2	\args
.endm

.altmacro
.macro load_single	index:req,regs:vararg
	load_init_word	%num_pipelines,\index,\regs
.endm

.macro save_single	index:req,regs:vararg
	save_word	%num_pipelines,\index,\regs
.endm

.macro load_quad	idx0:req,idx1:req,idx2:req,idx3:req,regs:vararg
	load_word	%num_pipelines,\idx0,\idx1,\idx2,\idx3,\regs
.endm

.macro load_hash	regs:vararg
	load_abcde	%num_pipelines,\regs
.endm

.macro save_hash	regs:vararg
	save_abcde	%num_pipelines,\regs
.endm

.macro SHA1_STEP_00_15_x1 windex:req
	load_single	\windex,WORD_0
	// e = (a leftrotate 5) + f + e + k + w[i]
	rotate_left	VT_0,VA_0,VT0_0,5
	add	VE_0.s,VE_0.s,VK.s
	revb	WORD_0.s, p0/m, WORD_0.s
	// macro F = (D ^ (B & (C ^ D)))
	eor	VF_0.d,VC_0.d,VD_0.d
	add	VE_0.s,VE_0.s,WORD_0.s
	save_single	\windex,WORD_0
	and	VF_0.d,VF_0.d,VB_0.d
	add	VE_0.s,VE_0.s,VT_0.s
	eor	VF_0.d,VF_0.d,VD_0.d
	rotate_left	VB_0,VB_0,VT0_0,30
	add	VE_0.s,VE_0.s,VF_0.s
.endm

.macro SHA1_STEP_00_15_x2 windex:req
	load_single	\windex,WORD_0,WORD_1
	// e = (a leftrotate 5) + f + e + k + w[i]
	rotate_left	VT_0,VA_0,VT0_0,5,VT_1,VA_1,VT0_1,5
	add	VE_0.s,VE_0.s,VK.s
	add	VE_1.s,VE_1.s,VK.s
	revb	WORD_0.s, p0/m, WORD_0.s
	revb	WORD_1.s, p0/m, WORD_1.s
	// macro F = (D ^ (B & (C ^ D)))
	eor	VF_0.d,VC_0.d,VD_0.d
	eor	VF_1.d,VC_1.d,VD_1.d
	add	VE_0.s,VE_0.s,WORD_0.s
	add	VE_1.s,VE_1.s,WORD_1.s
	save_single	\windex,WORD_0,WORD_1
	and	VF_0.d,VF_0.d,VB_0.d
	and	VF_1.d,VF_1.d,VB_1.d
	add	VE_0.s,VE_0.s,VT_0.s
	add	VE_1.s,VE_1.s,VT_1.s
	eor	VF_0.d,VF_0.d,VD_0.d
	eor	VF_1.d,VF_1.d,VD_1.d
	rotate_left	VB_0,VB_0,VT0_0,30,VB_1,VB_1,VT0_1,30
	add	VE_0.s,VE_0.s,VF_0.s
	add	VE_1.s,VE_1.s,VF_1.s
.endm

.macro SHA1_STEP_16_19_x1 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0
	add	VE_0.s,VE_0.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1
	.endif

	// macro F = (D ^ (B & (C ^ D)))
	eor	VF_0.d,VC_0.d,VD_0.d
	rotate_left	VT_0,VA_0,VT0_0,5
	and	VF_0.d,VF_0.d,VB_0.d
	add	VE_0.s,VE_0.s,WORD16_0.s
	save_single	\idx16,WORD16_0
	eor	VF_0.d,VF_0.d,VD_0.d
	add	VE_0.s,VE_0.s,VT_0.s
	rotate_left	VB_0,VB_0,VT0_0,30
	add	VE_0.s,VE_0.s,VF_0.s
.endm

.macro SHA1_STEP_16_19_x2 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0,WORD3_1,WORD8_1,WORD14_1,WORD16_1
	add	VE_0.s,VE_0.s,VK.s
	add	VE_1.s,VE_1.s,VK.s

	// macro F = (D ^ (B & (C ^ D)))
	eor	VF_0.d,VC_0.d,VD_0.d
	eor	VF_1.d,VC_1.d,VD_1.d
	rotate_left	VT_0,VA_0,VT0_0,5,VT_1,VA_1,VT0_1,5

	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		eor3	WORD16_1.d,WORD16_1.d,WORD3_1.d,WORD8_1.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
		xar	WORD16_1.s,WORD16_1.s,WORD14_1.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT0_1.d,WORD3_1.d,WORD8_1.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	VT1_1.d,WORD14_1.d,WORD16_1.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	WORD16_1.d,VT0_1.d,VT1_1.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1,WORD16_1,WORD16_1,VT0_1,1
	.endif

	and	VF_0.d,VF_0.d,VB_0.d
	and	VF_1.d,VF_1.d,VB_1.d
	add	VE_0.s,VE_0.s,WORD16_0.s
	add	VE_1.s,VE_1.s,WORD16_1.s
	save_single	\idx16,WORD16_0,WORD16_1
	eor	VF_0.d,VF_0.d,VD_0.d
	eor	VF_1.d,VF_1.d,VD_1.d
	add	VE_0.s,VE_0.s,VT_0.s
	add	VE_1.s,VE_1.s,VT_1.s
	rotate_left	VB_0,VB_0,VT0_0,30,VB_1,VB_1,VT0_1,30
	add	VE_0.s,VE_0.s,VF_0.s
	add	VE_1.s,VE_1.s,VF_1.s
.endm

.macro SHA1_STEP_20_39_x1 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0
	add	VE_0.s,VE_0.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		movprfx	VF_0,VB_0
		eor3	VF_0.d,VF_0.d,VC_0.d,VD_0.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		// F = (B ^ C ^ D)
		eor	VF_0.d,VB_0.d,VC_0.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	VF_0.d,VF_0.d,VD_0.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1
	.endif

	add	VE_0.s,VE_0.s,WORD16_0.s
	save_single	\idx16,WORD16_0
	rotate_left	VT_0,VA_0,VT0_0,5
	add	VE_0.s,VE_0.s,VT_0.s
	rotate_left	VB_0,VB_0,VT0_0,30
	add	VE_0.s,VE_0.s,VF_0.s
.endm

.macro SHA1_STEP_20_39_x2 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0,WORD3_1,WORD8_1,WORD14_1,WORD16_1
	add	VE_0.s,VE_0.s,VK.s
	add	VE_1.s,VE_1.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		eor3	WORD16_1.d,WORD16_1.d,WORD3_1.d,WORD8_1.d
		movprfx	VF_0,VB_0
		eor3	VF_0.d,VF_0.d,VC_0.d,VD_0.d
		movprfx	VF_1,VB_1
		eor3	VF_1.d,VF_1.d,VC_1.d,VD_1.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
		xar	WORD16_1.s,WORD16_1.s,WORD14_1.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT0_1.d,WORD3_1.d,WORD8_1.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	VT1_1.d,WORD14_1.d,WORD16_1.d
		// F = (B ^ C ^ D)
		eor	VF_0.d,VB_0.d,VC_0.d
		eor	VF_1.d,VB_1.d,VC_1.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	WORD16_1.d,VT0_1.d,VT1_1.d
		eor	VF_0.d,VF_0.d,VD_0.d
		eor	VF_1.d,VF_1.d,VD_1.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1,WORD16_1,WORD16_1,VT0_1,1
	.endif

	add	VE_0.s,VE_0.s,WORD16_0.s
	add	VE_1.s,VE_1.s,WORD16_1.s
	save_single	\idx16,WORD16_0,WORD16_1
	rotate_left	VT_0,VA_0,VT0_0,5,VT_1,VA_1,VT0_1,5
	add	VE_0.s,VE_0.s,VT_0.s
	add	VE_1.s,VE_1.s,VT_1.s
	rotate_left	VB_0,VB_0,VT0_0,30,VB_1,VB_1,VT0_1,30
	add	VE_0.s,VE_0.s,VF_0.s
	add	VE_1.s,VE_1.s,VF_1.s
.endm

.macro SHA1_STEP_40_59_x1 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0
	add	VE_0.s,VE_0.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1
	.endif

	// F = ((B & C) | (B & D) | (C & D))
	orr	VF_0.d,VB_0.d,VC_0.d
	and	VT_0.d,VB_0.d,VC_0.d
	and	VF_0.d,VF_0.d,VD_0.d
	orr	VF_0.d,VF_0.d,VT_0.d

	rotate_left	VT_0,VA_0,VT0_0,5
	add	VE_0.s,VE_0.s,WORD16_0.s
	save_single	\idx16,WORD16_0
	add	VE_0.s,VE_0.s,VT_0.s
	rotate_left	VB_0,VB_0,VT0_0,30
	add	VE_0.s,VE_0.s,VF_0.s
.endm

.macro SHA1_STEP_40_59_x2 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0,WORD3_1,WORD8_1,WORD14_1,WORD16_1
	add	VE_0.s,VE_0.s,VK.s
	add	VE_1.s,VE_1.s,VK.s

	// F = ((B & C) | (B & D) | (C & D))
	orr	VF_0.d,VB_0.d,VC_0.d
	orr	VF_1.d,VB_1.d,VC_1.d
	and	VT_0.d,VB_0.d,VC_0.d
	and	VT_1.d,VB_1.d,VC_1.d
	and	VF_0.d,VF_0.d,VD_0.d
	and	VF_1.d,VF_1.d,VD_1.d
	orr	VF_0.d,VF_0.d,VT_0.d
	orr	VF_1.d,VF_1.d,VT_1.d

	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		eor3	WORD16_1.d,WORD16_1.d,WORD3_1.d,WORD8_1.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
		xar	WORD16_1.s,WORD16_1.s,WORD14_1.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT0_1.d,WORD3_1.d,WORD8_1.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	VT1_1.d,WORD14_1.d,WORD16_1.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	WORD16_1.d,VT0_1.d,VT1_1.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1
		rotate_left	WORD16_1,WORD16_1,VT0_1,1
	.endif

	rotate_left	VT_0,VA_0,VT0_0,5,VT_1,VA_1,VT0_1,5
	add	VE_0.s,VE_0.s,WORD16_0.s
	add	VE_1.s,VE_1.s,WORD16_1.s
	save_single	\idx16,WORD16_0,WORD16_1
	add	VE_0.s,VE_0.s,VT_0.s
	add	VE_1.s,VE_1.s,VT_1.s
	rotate_left	VB_0,VB_0,VT0_0,30,VB_1,VB_1,VT0_1,30
	add	VE_0.s,VE_0.s,VF_0.s
	add	VE_1.s,VE_1.s,VF_1.s
.endm

.macro SHA1_STEP_60_79_x1 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0
	add	VE_0.s,VE_0.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		movprfx	VF_0,VB_0
		eor3	VF_0.d,VF_0.d,VC_0.d,VD_0.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		// F = (B ^ C ^ D)
		eor	VF_0.d,VB_0.d,VC_0.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	VF_0.d,VF_0.d,VD_0.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1
	.endif
	add	VE_0.s,VE_0.s,WORD16_0.s
	save_single	\idx16,WORD16_0
	.if	\windex == 79
		load_hash	TMPV0,TMPV1,TMPV2,TMPV3,TMPV4
	.else
		save_single	\idx16,WORD16_0
	.endif
	rotate_left	VT_0,VA_0,VT0_0,5
	add	VE_0.s,VE_0.s,VT_0.s
	rotate_left	VB_0,VB_0,VT0_0,30
	add	VE_0.s,VE_0.s,VF_0.s
.endm

.macro SHA1_STEP_60_79_x2 windex:req,idx3:req,idx8:req,idx14:req,idx16:req
	load_quad	\idx3,\idx8,\idx14,\idx16,WORD3_0,WORD8_0,WORD14_0,WORD16_0,WORD3_1,WORD8_1,WORD14_1,WORD16_1
	add	VE_0.s,VE_0.s,VK.s
	add	VE_1.s,VE_1.s,VK.s
	.if have_sve2 == 1
		eor3	WORD16_0.d,WORD16_0.d,WORD3_0.d,WORD8_0.d
		eor3	WORD16_1.d,WORD16_1.d,WORD3_1.d,WORD8_1.d
		movprfx	VF_0,VB_0
		eor3	VF_0.d,VF_0.d,VC_0.d,VD_0.d
		movprfx	VF_1,VB_1
		eor3	VF_1.d,VF_1.d,VC_1.d,VD_1.d
		xar	WORD16_0.s,WORD16_0.s,WORD14_0.s,32-1
		xar	WORD16_1.s,WORD16_1.s,WORD14_1.s,32-1
	.else
		eor	VT0_0.d,WORD3_0.d,WORD8_0.d
		eor	VT0_1.d,WORD3_1.d,WORD8_1.d
		eor	VT1_0.d,WORD14_0.d,WORD16_0.d
		eor	VT1_1.d,WORD14_1.d,WORD16_1.d
		// F = (B ^ C ^ D)
		eor	VF_0.d,VB_0.d,VC_0.d
		eor	VF_1.d,VB_1.d,VC_1.d
		eor	WORD16_0.d,VT0_0.d,VT1_0.d
		eor	WORD16_1.d,VT0_1.d,VT1_1.d
		eor	VF_0.d,VF_0.d,VD_0.d
		eor	VF_1.d,VF_1.d,VD_1.d
		rotate_left	WORD16_0,WORD16_0,VT0_0,1,WORD16_1,WORD16_1,VT0_1,1
	.endif
	add	VE_0.s,VE_0.s,WORD16_0.s
	add	VE_1.s,VE_1.s,WORD16_1.s
	.if	\windex == 79
		load_hash	TMPV0,TMPV1,TMPV2,TMPV3,TMPV4,TMPV0X,TMPV1X,TMPV2X,TMPV3X,TMPV4X
	.else
		save_single	\idx16,WORD16_0,WORD16_1
	.endif
	rotate_left	VT_0,VA_0,VT0_0,5,VT_1,VA_1,VT0_1,5
	add	VE_0.s,VE_0.s,VT_0.s
	add	VE_1.s,VE_1.s,VT_1.s
	rotate_left	VB_0,VB_0,VT0_0,30,VB_1,VB_1,VT0_1,30
	add	VE_0.s,VE_0.s,VF_0.s
	add	VE_1.s,VE_1.s,VF_1.s
.endm

.macro SWAP_STATES
	.unreq TT
	TT .req VE_0
	.unreq VE_0
	VE_0 .req VD_0
	.unreq VD_0
	VD_0 .req VC_0
	.unreq VC_0
	VC_0 .req VB_0
	.unreq VB_0
	VB_0 .req VA_0
	.unreq VA_0
	VA_0 .req TT

	.unreq TT
	TT .req VE_1
	.unreq VE_1
	VE_1 .req VD_1
	.unreq VD_1
	VD_1 .req VC_1
	.unreq VC_1
	VC_1 .req VB_1
	.unreq VB_1
	VB_1 .req VA_1
	.unreq VA_1
	VA_1 .req TT
.endm

.altmacro
.macro WRAPPER pipelines:req,step:req,args:vararg
	SHA1_\step\()_x\pipelines\()	\args
.endm

.macro exec_step windex:req
	.if \windex <= 15
		WRAPPER	%num_pipelines,STEP_00_15,\windex
	.else
		idx14=((\windex - 14) & 15)
		idx8=((\windex - 8) & 15)
		idx3=((\windex - 3) & 15)
		idx16=(\windex & 15)
		.if \windex <= 19
			WRAPPER %num_pipelines,STEP_16_19,\windex,%idx3,%idx8,%idx14,%idx16
		.endif
		.if \windex >= 20 && \windex <= 39
			WRAPPER %num_pipelines,STEP_20_39,\windex,%idx3,%idx8,%idx14,%idx16
		.endif
		.if \windex >= 40 && \windex <= 59
			WRAPPER %num_pipelines,STEP_40_59,\windex,%idx3,%idx8,%idx14,%idx16
		.endif
		.if \windex >= 60 && \windex <= 79
			WRAPPER %num_pipelines,STEP_60_79,\windex,%idx3,%idx8,%idx14,%idx16
		.endif
	.endif
	SWAP_STATES
.endm

.macro exec_steps idx:req,more:vararg
	exec_step	\idx
	.ifnb \more
		exec_steps	\more
	.endif
.endm

.macro finish_x1
	add	VA_0.s,VA_0.s,TMPV0.s
	add	VB_0.s,VB_0.s,TMPV1.s
	add	VC_0.s,VC_0.s,TMPV2.s
	add	VD_0.s,VD_0.s,TMPV3.s
	add	VE_0.s,VE_0.s,TMPV4.s
	save_hash	VA_0,VB_0,VC_0,VD_0,VE_0
.endm

.macro finish_x2
	add	VA_0.s,VA_0.s,TMPV0.s
	add	VA_1.s,VA_1.s,TMPV0X.s
	add	VB_0.s,VB_0.s,TMPV1.s
	add	VB_1.s,VB_1.s,TMPV1X.s
	add	VC_0.s,VC_0.s,TMPV2.s
	add	VC_1.s,VC_1.s,TMPV2X.s
	add	VD_0.s,VD_0.s,TMPV3.s
	add	VD_1.s,VD_1.s,TMPV3X.s
	add	VE_0.s,VE_0.s,TMPV4.s
	add	VE_1.s,VE_1.s,TMPV4X.s
	save_hash	VA_0,VB_0,VC_0,VD_0,VE_0,VA_1,VB_1,VC_1,VD_1,VE_1
.endm

.macro sha1_single	pipelines:req,sve2_flag:req
	.if	\sve2_flag == 1
		have_sve2=1
		eor	VZERO.d,VZERO.d,VZERO.d
	.else
		have_sve2=0
	.endif
	num_pipelines=\pipelines
	load_init
	ld1rw   {VK.s},p0/z,[sha1key_adr]
	exec_steps	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
	// 20 ~ 39
	ld1rw   {VK.s},p0/z,[sha1key_adr,4]
	exec_steps	20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39
	// 40 ~ 59
	ld1rw   {VK.s},p0/z,[sha1key_adr,8]
	exec_steps	40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59
	// 60 ~ 79
	ld1rw   {VK.s},p0/z,[sha1key_adr,12]
	exec_steps	60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79
	finish_x\pipelines\()
.endm

.macro sha1_sve_save_stack
	stp	d8,d9,[sp, -48]!
	stp	d10,d11,[sp, 16]
	stp	d12,d13,[sp, 32]
.endm

.macro sha1_sve_restore_stack
	ldp	d10,d11,[sp, 16]
	ldp	d12,d13,[sp, 32]
	ldp	d8,d9,[sp],48
.endm

	.section .rodata.cst16,"aM",@progbits,16
	.align  16
SHA1KEY:
	.word	0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6
