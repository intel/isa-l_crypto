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

%include "reg_sizes.asm"
%include "multibinary.asm"
default rel
[bits 64]

; declare the L3 ctx level symbols (these will then call the appropriate
; L2 symbols)
extern _md5_ctx_mgr_init_sse
extern _md5_ctx_mgr_submit_sse
extern _md5_ctx_mgr_flush_sse

extern _md5_ctx_mgr_init_avx
extern _md5_ctx_mgr_submit_avx
extern _md5_ctx_mgr_flush_avx

extern _md5_ctx_mgr_init_avx2
extern _md5_ctx_mgr_submit_avx2
extern _md5_ctx_mgr_flush_avx2

extern _md5_ctx_mgr_init_avx512
extern _md5_ctx_mgr_submit_avx512
extern _md5_ctx_mgr_flush_avx512

extern _md5_ctx_mgr_init_base
extern _md5_ctx_mgr_submit_base
extern _md5_ctx_mgr_flush_base

;;; *_mbinit are initial values for *_dispatched; is updated on first call.
;;; Therefore, *_dispatch_init is only executed on first call.

; Initialise symbols
mbin_interface _md5_ctx_mgr_init
mbin_interface _md5_ctx_mgr_submit
mbin_interface _md5_ctx_mgr_flush

mbin_dispatch_init6 _md5_ctx_mgr_init, _md5_ctx_mgr_init_base, _md5_ctx_mgr_init_sse, _md5_ctx_mgr_init_avx, _md5_ctx_mgr_init_avx2, _md5_ctx_mgr_init_avx512
mbin_dispatch_init6 _md5_ctx_mgr_submit, _md5_ctx_mgr_submit_base, _md5_ctx_mgr_submit_sse, _md5_ctx_mgr_submit_avx, _md5_ctx_mgr_submit_avx2, _md5_ctx_mgr_submit_avx512
mbin_dispatch_init6 _md5_ctx_mgr_flush, _md5_ctx_mgr_flush_base, _md5_ctx_mgr_flush_sse, _md5_ctx_mgr_flush_avx, _md5_ctx_mgr_flush_avx2, _md5_ctx_mgr_flush_avx512

;;       func                  core, ver, snum
slversion _md5_ctx_mgr_init,	00,   04,  0189
slversion _md5_ctx_mgr_submit,	00,   04,  018a
slversion _md5_ctx_mgr_flush,	00,   04,  018b
