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

%ifidn __OUTPUT_FORMAT__, elf64
%define WRT_OPT         wrt ..plt
%else
%define WRT_OPT
%endif

%include "reg_sizes.asm"

extern aesni_gcm128_init_sse
extern aesni_gcm128_init_avx_gen4
extern aesni_gcm128_init_avx_gen2

extern aesni_gcm128_enc_sse
extern aesni_gcm128_enc_avx_gen4
extern aesni_gcm128_enc_avx_gen2
extern aesni_gcm128_enc_update_sse
extern aesni_gcm128_enc_update_avx_gen4
extern aesni_gcm128_enc_update_avx_gen2
extern aesni_gcm128_enc_finalize_sse
extern aesni_gcm128_enc_finalize_avx_gen4
extern aesni_gcm128_enc_finalize_avx_gen2

extern aesni_gcm128_dec_sse
extern aesni_gcm128_dec_avx_gen4
extern aesni_gcm128_dec_avx_gen2
extern aesni_gcm128_dec_update_sse
extern aesni_gcm128_dec_update_avx_gen4
extern aesni_gcm128_dec_update_avx_gen2
extern aesni_gcm128_dec_finalize_sse
extern aesni_gcm128_dec_finalize_avx_gen4
extern aesni_gcm128_dec_finalize_avx_gen2

extern aesni_gcm128_precomp_sse
extern aesni_gcm128_precomp_avx_gen4
extern aesni_gcm128_precomp_avx_gen2



extern aesni_gcm256_init_sse
extern aesni_gcm256_init_avx_gen4
extern aesni_gcm256_init_avx_gen2

extern aesni_gcm256_enc_sse
extern aesni_gcm256_enc_avx_gen4
extern aesni_gcm256_enc_avx_gen2
extern aesni_gcm256_enc_update_sse
extern aesni_gcm256_enc_update_avx_gen4
extern aesni_gcm256_enc_update_avx_gen2
extern aesni_gcm256_enc_finalize_sse
extern aesni_gcm256_enc_finalize_avx_gen4
extern aesni_gcm256_enc_finalize_avx_gen2

extern aesni_gcm256_dec_sse
extern aesni_gcm256_dec_avx_gen4
extern aesni_gcm256_dec_avx_gen2
extern aesni_gcm256_dec_update_sse
extern aesni_gcm256_dec_update_avx_gen4
extern aesni_gcm256_dec_update_avx_gen2
extern aesni_gcm256_dec_finalize_sse
extern aesni_gcm256_dec_finalize_avx_gen4
extern aesni_gcm256_dec_finalize_avx_gen2

extern aesni_gcm256_precomp_sse
extern aesni_gcm256_precomp_avx_gen4
extern aesni_gcm256_precomp_avx_gen2

section .text

%include "multibinary.asm"

;;;;
; instantiate aesni_gcm interfaces init, enc, enc_update, enc_finalize, dec, dec_update, dec_finalize and precomp
;;;;
mbin_interface     aesni_gcm128_init
mbin_dispatch_init aesni_gcm128_init, aesni_gcm128_init_sse, aesni_gcm128_init_avx_gen2, aesni_gcm128_init_avx_gen4

mbin_interface     aesni_gcm128_enc
mbin_dispatch_init aesni_gcm128_enc, aesni_gcm128_enc_sse, aesni_gcm128_enc_avx_gen2, aesni_gcm128_enc_avx_gen4

mbin_interface     aesni_gcm128_enc_update
mbin_dispatch_init aesni_gcm128_enc_update, aesni_gcm128_enc_update_sse, aesni_gcm128_enc_update_avx_gen2, aesni_gcm128_enc_update_avx_gen4

mbin_interface     aesni_gcm128_enc_finalize
mbin_dispatch_init aesni_gcm128_enc_finalize, aesni_gcm128_enc_finalize_sse, aesni_gcm128_enc_finalize_avx_gen2, aesni_gcm128_enc_finalize_avx_gen4

mbin_interface     aesni_gcm128_dec
mbin_dispatch_init aesni_gcm128_dec, aesni_gcm128_dec_sse, aesni_gcm128_dec_avx_gen2, aesni_gcm128_dec_avx_gen4

mbin_interface     aesni_gcm128_dec_update
mbin_dispatch_init aesni_gcm128_dec_update, aesni_gcm128_dec_update_sse, aesni_gcm128_dec_update_avx_gen2, aesni_gcm128_dec_update_avx_gen4

mbin_interface     aesni_gcm128_dec_finalize
mbin_dispatch_init aesni_gcm128_dec_finalize, aesni_gcm128_dec_finalize_sse, aesni_gcm128_dec_finalize_avx_gen2, aesni_gcm128_dec_finalize_avx_gen4

mbin_interface     aesni_gcm128_precomp
mbin_dispatch_init aesni_gcm128_precomp, aesni_gcm128_precomp_sse, aesni_gcm128_precomp_avx_gen2, aesni_gcm128_precomp_avx_gen4

;;;;
; instantiate aesni_gcm interfaces init, enc, enc_update, enc_finalize, dec, dec_update, dec_finalize and precomp
;;;;
mbin_interface     aesni_gcm256_init
mbin_dispatch_init aesni_gcm256_init, aesni_gcm256_init_sse, aesni_gcm256_init_avx_gen2, aesni_gcm256_init_avx_gen4

mbin_interface     aesni_gcm256_enc
mbin_dispatch_init aesni_gcm256_enc, aesni_gcm256_enc_sse, aesni_gcm256_enc_avx_gen2, aesni_gcm256_enc_avx_gen4

mbin_interface     aesni_gcm256_enc_update
mbin_dispatch_init aesni_gcm256_enc_update, aesni_gcm256_enc_update_sse, aesni_gcm256_enc_update_avx_gen2, aesni_gcm256_enc_update_avx_gen4

mbin_interface     aesni_gcm256_enc_finalize
mbin_dispatch_init aesni_gcm256_enc_finalize, aesni_gcm256_enc_finalize_sse, aesni_gcm256_enc_finalize_avx_gen2, aesni_gcm256_enc_finalize_avx_gen4

mbin_interface     aesni_gcm256_dec
mbin_dispatch_init aesni_gcm256_dec, aesni_gcm256_dec_sse, aesni_gcm256_dec_avx_gen2, aesni_gcm256_dec_avx_gen4

mbin_interface     aesni_gcm256_dec_update
mbin_dispatch_init aesni_gcm256_dec_update, aesni_gcm256_dec_update_sse, aesni_gcm256_dec_update_avx_gen2, aesni_gcm256_dec_update_avx_gen4

mbin_interface     aesni_gcm256_dec_finalize
mbin_dispatch_init aesni_gcm256_dec_finalize, aesni_gcm256_dec_finalize_sse, aesni_gcm256_dec_finalize_avx_gen2, aesni_gcm256_dec_finalize_avx_gen4

mbin_interface     aesni_gcm256_precomp
mbin_dispatch_init aesni_gcm256_precomp, aesni_gcm256_precomp_sse, aesni_gcm256_precomp_avx_gen2, aesni_gcm256_precomp_avx_gen4


;;;       func				core, ver, snum
slversion aesni_gcm128_enc,		00,   00,  0280
slversion aesni_gcm128_dec,		00,   00,  0281
slversion aesni_gcm128_init,		00,   00,  0282
slversion aesni_gcm128_enc_update,	00,   00,  0283
slversion aesni_gcm128_dec_update,	00,   00,  0284
slversion aesni_gcm128_enc_finalize,	00,   00,  0285
slversion aesni_gcm128_dec_finalize,	00,   00,  0286
slversion aesni_gcm256_enc,		00,   00,  0288
slversion aesni_gcm256_dec,		00,   00,  0289
slversion aesni_gcm256_init,		00,   00,  028a
slversion aesni_gcm256_enc_update,	00,   00,  028b
slversion aesni_gcm256_dec_update,	00,   00,  028c
slversion aesni_gcm256_enc_finalize,	00,   00,  028d
slversion aesni_gcm256_dec_finalize,	00,   00,  028e
