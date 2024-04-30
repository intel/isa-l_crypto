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

default rel
[bits 64]

%include "reg_sizes.asm"

extern _aes_gcm_init_128_sse
extern _aes_gcm_init_128_avx_gen4
extern _aes_gcm_init_128_avx_gen2

extern _aes_gcm_enc_128_sse
extern _aes_gcm_enc_128_avx_gen4
extern _aes_gcm_enc_128_avx_gen2
extern _aes_gcm_enc_128_update_sse
extern _aes_gcm_enc_128_update_avx_gen4
extern _aes_gcm_enc_128_update_avx_gen2
extern _aes_gcm_enc_128_finalize_sse
extern _aes_gcm_enc_128_finalize_avx_gen4
extern _aes_gcm_enc_128_finalize_avx_gen2

extern _aes_gcm_dec_128_sse
extern _aes_gcm_dec_128_avx_gen4
extern _aes_gcm_dec_128_avx_gen2
extern _aes_gcm_dec_128_update_sse
extern _aes_gcm_dec_128_update_avx_gen4
extern _aes_gcm_dec_128_update_avx_gen2
extern _aes_gcm_dec_128_finalize_sse
extern _aes_gcm_dec_128_finalize_avx_gen4
extern _aes_gcm_dec_128_finalize_avx_gen2

extern _aes_gcm_precomp_128_sse
extern _aes_gcm_precomp_128_avx_gen4
extern _aes_gcm_precomp_128_avx_gen2

extern _aes_gcm_init_256_sse
extern _aes_gcm_init_256_avx_gen4
extern _aes_gcm_init_256_avx_gen2

extern _aes_gcm_enc_256_sse
extern _aes_gcm_enc_256_avx_gen4
extern _aes_gcm_enc_256_avx_gen2
extern _aes_gcm_enc_256_update_sse
extern _aes_gcm_enc_256_update_avx_gen4
extern _aes_gcm_enc_256_update_avx_gen2
extern _aes_gcm_enc_256_finalize_sse
extern _aes_gcm_enc_256_finalize_avx_gen4
extern _aes_gcm_enc_256_finalize_avx_gen2

extern _aes_gcm_dec_256_sse
extern _aes_gcm_dec_256_avx_gen4
extern _aes_gcm_dec_256_avx_gen2
extern _aes_gcm_dec_256_update_sse
extern _aes_gcm_dec_256_update_avx_gen4
extern _aes_gcm_dec_256_update_avx_gen2
extern _aes_gcm_dec_256_finalize_sse
extern _aes_gcm_dec_256_finalize_avx_gen4
extern _aes_gcm_dec_256_finalize_avx_gen2

extern _aes_gcm_precomp_256_sse
extern _aes_gcm_precomp_256_avx_gen4
extern _aes_gcm_precomp_256_avx_gen2

%if (AS_FEATURE_LEVEL) >= 10
extern _aes_gcm_precomp_128_vaes_avx512
extern _aes_gcm_init_128_vaes_avx512
extern _aes_gcm_enc_128_update_vaes_avx512
extern _aes_gcm_dec_128_update_vaes_avx512
extern _aes_gcm_enc_128_finalize_vaes_avx512
extern _aes_gcm_dec_128_finalize_vaes_avx512
extern _aes_gcm_enc_128_vaes_avx512
extern _aes_gcm_dec_128_vaes_avx512

extern _aes_gcm_precomp_256_vaes_avx512
extern _aes_gcm_init_256_vaes_avx512
extern _aes_gcm_enc_256_update_vaes_avx512
extern _aes_gcm_dec_256_update_vaes_avx512
extern _aes_gcm_enc_256_finalize_vaes_avx512
extern _aes_gcm_dec_256_finalize_vaes_avx512
extern _aes_gcm_enc_256_vaes_avx512
extern _aes_gcm_dec_256_vaes_avx512
%endif

section .text

%include "multibinary.asm"

;;;;
; instantiate aesni_gcm interfaces init, enc, enc_update, enc_finalize, dec, dec_update, dec_finalize and precomp
;;;;
mbin_interface     _aes_gcm_init_128
mbin_dispatch_init7 _aes_gcm_init_128, _aes_gcm_init_128_sse, _aes_gcm_init_128_sse, _aes_gcm_init_128_avx_gen2, _aes_gcm_init_128_avx_gen4, _aes_gcm_init_128_avx_gen4, _aes_gcm_init_128_vaes_avx512

mbin_interface     _aes_gcm_enc_128
mbin_dispatch_init7 _aes_gcm_enc_128, _aes_gcm_enc_128_sse, _aes_gcm_enc_128_sse, _aes_gcm_enc_128_avx_gen2, _aes_gcm_enc_128_avx_gen4, _aes_gcm_enc_128_avx_gen4, _aes_gcm_enc_128_vaes_avx512

mbin_interface     _aes_gcm_enc_128_update
mbin_dispatch_init7 _aes_gcm_enc_128_update, _aes_gcm_enc_128_update_sse, _aes_gcm_enc_128_update_sse, _aes_gcm_enc_128_update_avx_gen2, _aes_gcm_enc_128_update_avx_gen4, _aes_gcm_enc_128_update_avx_gen4, _aes_gcm_enc_128_update_vaes_avx512

mbin_interface     _aes_gcm_enc_128_finalize
mbin_dispatch_init7 _aes_gcm_enc_128_finalize, _aes_gcm_enc_128_finalize_sse, _aes_gcm_enc_128_finalize_sse, _aes_gcm_enc_128_finalize_avx_gen2, _aes_gcm_enc_128_finalize_avx_gen4, _aes_gcm_enc_128_finalize_avx_gen4, _aes_gcm_enc_128_finalize_vaes_avx512

mbin_interface     _aes_gcm_dec_128
mbin_dispatch_init7 _aes_gcm_dec_128, _aes_gcm_dec_128_sse, _aes_gcm_dec_128_sse, _aes_gcm_dec_128_avx_gen2, _aes_gcm_dec_128_avx_gen4, _aes_gcm_dec_128_avx_gen4, _aes_gcm_dec_128_vaes_avx512

mbin_interface     _aes_gcm_dec_128_update
mbin_dispatch_init7 _aes_gcm_dec_128_update, _aes_gcm_dec_128_update_sse, _aes_gcm_dec_128_update_sse, _aes_gcm_dec_128_update_avx_gen2, _aes_gcm_dec_128_update_avx_gen4, _aes_gcm_dec_128_update_avx_gen4, _aes_gcm_dec_128_update_vaes_avx512

mbin_interface     _aes_gcm_dec_128_finalize
mbin_dispatch_init7 _aes_gcm_dec_128_finalize, _aes_gcm_dec_128_finalize_sse, _aes_gcm_dec_128_finalize_sse, _aes_gcm_dec_128_finalize_avx_gen2, _aes_gcm_dec_128_finalize_avx_gen4, _aes_gcm_dec_128_finalize_avx_gen4, _aes_gcm_dec_128_finalize_vaes_avx512

mbin_interface     _aes_gcm_precomp_128
mbin_dispatch_init7 _aes_gcm_precomp_128, _aes_gcm_precomp_128_sse, _aes_gcm_precomp_128_sse, _aes_gcm_precomp_128_avx_gen2, _aes_gcm_precomp_128_avx_gen4, _aes_gcm_precomp_128_avx_gen4, _aes_gcm_precomp_128_vaes_avx512

;;;;
; instantiate aesni_gcm interfaces init, enc, enc_update, enc_finalize, dec, dec_update, dec_finalize and precomp
;;;;
mbin_interface     _aes_gcm_init_256
mbin_dispatch_init7 _aes_gcm_init_256, _aes_gcm_init_256_sse, _aes_gcm_init_256_sse, _aes_gcm_init_256_avx_gen2, _aes_gcm_init_256_avx_gen4, _aes_gcm_init_256_avx_gen4, _aes_gcm_init_256_vaes_avx512

mbin_interface     _aes_gcm_enc_256
mbin_dispatch_init7 _aes_gcm_enc_256, _aes_gcm_enc_256_sse, _aes_gcm_enc_256_sse, _aes_gcm_enc_256_avx_gen2, _aes_gcm_enc_256_avx_gen4, _aes_gcm_enc_256_avx_gen4, _aes_gcm_enc_256_vaes_avx512

mbin_interface     _aes_gcm_enc_256_update
mbin_dispatch_init7 _aes_gcm_enc_256_update, _aes_gcm_enc_256_update_sse, _aes_gcm_enc_256_update_sse, _aes_gcm_enc_256_update_avx_gen2, _aes_gcm_enc_256_update_avx_gen4, _aes_gcm_enc_256_update_avx_gen4, _aes_gcm_enc_256_update_vaes_avx512

mbin_interface     _aes_gcm_enc_256_finalize
mbin_dispatch_init7 _aes_gcm_enc_256_finalize, _aes_gcm_enc_256_finalize_sse, _aes_gcm_enc_256_finalize_sse, _aes_gcm_enc_256_finalize_avx_gen2, _aes_gcm_enc_256_finalize_avx_gen4, _aes_gcm_enc_256_finalize_avx_gen4, _aes_gcm_enc_256_finalize_vaes_avx512

mbin_interface     _aes_gcm_dec_256
mbin_dispatch_init7 _aes_gcm_dec_256, _aes_gcm_dec_256_sse, _aes_gcm_dec_256_sse, _aes_gcm_dec_256_avx_gen2, _aes_gcm_dec_256_avx_gen4, _aes_gcm_dec_256_avx_gen4, _aes_gcm_dec_256_vaes_avx512

mbin_interface     _aes_gcm_dec_256_update
mbin_dispatch_init7 _aes_gcm_dec_256_update, _aes_gcm_dec_256_update_sse, _aes_gcm_dec_256_update_sse, _aes_gcm_dec_256_update_avx_gen2, _aes_gcm_dec_256_update_avx_gen4, _aes_gcm_dec_256_update_avx_gen4, _aes_gcm_dec_256_update_vaes_avx512

mbin_interface     _aes_gcm_dec_256_finalize
mbin_dispatch_init7 _aes_gcm_dec_256_finalize, _aes_gcm_dec_256_finalize_sse, _aes_gcm_dec_256_finalize_sse, _aes_gcm_dec_256_finalize_avx_gen2, _aes_gcm_dec_256_finalize_avx_gen4, _aes_gcm_dec_256_finalize_avx_gen4, _aes_gcm_dec_256_finalize_vaes_avx512

mbin_interface     _aes_gcm_precomp_256
mbin_dispatch_init7 _aes_gcm_precomp_256, _aes_gcm_precomp_256_sse, _aes_gcm_precomp_256_sse, _aes_gcm_precomp_256_avx_gen2, _aes_gcm_precomp_256_avx_gen4, _aes_gcm_precomp_256_avx_gen4, _aes_gcm_precomp_256_vaes_avx512


;;;       func				core, ver, snum
slversion _aes_gcm_enc_128,		00,   00,  02c0
slversion _aes_gcm_dec_128,		00,   00,  02c1
slversion _aes_gcm_init_128,		00,   00,  02c2
slversion _aes_gcm_enc_128_update,	00,   00,  02c3
slversion _aes_gcm_dec_128_update,	00,   00,  02c4
slversion _aes_gcm_enc_128_finalize,	00,   00,  02c5
slversion _aes_gcm_dec_128_finalize,	00,   00,  02c6
slversion _aes_gcm_enc_256,		00,   00,  02d0
slversion _aes_gcm_dec_256,		00,   00,  02d1
slversion _aes_gcm_init_256,		00,   00,  02d2
slversion _aes_gcm_enc_256_update,	00,   00,  02d3
slversion _aes_gcm_dec_256_update,	00,   00,  02d4
slversion _aes_gcm_enc_256_finalize,	00,   00,  02d5
slversion _aes_gcm_dec_256_finalize,	00,   00,  02d6
