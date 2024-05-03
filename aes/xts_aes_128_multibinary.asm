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

extern _XTS_AES_128_enc_sse
extern _XTS_AES_128_enc_avx

extern _XTS_AES_128_enc_expanded_key_sse
extern _XTS_AES_128_enc_expanded_key_avx

extern _XTS_AES_128_dec_sse
extern _XTS_AES_128_dec_avx

extern _XTS_AES_128_dec_expanded_key_sse
extern _XTS_AES_128_dec_expanded_key_avx

%if (AS_FEATURE_LEVEL) >= 10
extern _XTS_AES_128_enc_vaes
extern _XTS_AES_128_enc_expanded_key_vaes
extern _XTS_AES_128_dec_vaes
extern _XTS_AES_128_dec_expanded_key_vaes
%endif

section .text

%include "multibinary.asm"

;;;;
; instantiate _XTS_AES_128_enc, _XTS_AES_128_enc_expanded_key, _XTS_AES_128_dec, and _XTS_AES_128_dec_expanded_key
;;;;
mbin_interface     _XTS_AES_128_enc
mbin_dispatch_init7 _XTS_AES_128_enc, _XTS_AES_128_enc_sse, _XTS_AES_128_enc_sse, _XTS_AES_128_enc_avx, _XTS_AES_128_enc_avx, _XTS_AES_128_enc_avx, _XTS_AES_128_enc_vaes

mbin_interface     _XTS_AES_128_enc_expanded_key
mbin_dispatch_init7 _XTS_AES_128_enc_expanded_key, _XTS_AES_128_enc_expanded_key_sse, _XTS_AES_128_enc_expanded_key_sse, _XTS_AES_128_enc_expanded_key_avx, _XTS_AES_128_enc_expanded_key_avx, _XTS_AES_128_enc_expanded_key_avx, _XTS_AES_128_enc_expanded_key_vaes

mbin_interface     _XTS_AES_128_dec
mbin_dispatch_init7 _XTS_AES_128_dec, _XTS_AES_128_dec_sse, _XTS_AES_128_dec_sse, _XTS_AES_128_dec_avx, _XTS_AES_128_dec_avx, _XTS_AES_128_dec_avx, _XTS_AES_128_dec_vaes

mbin_interface     _XTS_AES_128_dec_expanded_key
mbin_dispatch_init7 _XTS_AES_128_dec_expanded_key, _XTS_AES_128_dec_expanded_key_sse, _XTS_AES_128_dec_expanded_key_sse, _XTS_AES_128_dec_expanded_key_avx, _XTS_AES_128_dec_expanded_key_avx, _XTS_AES_128_dec_expanded_key_avx, _XTS_AES_128_dec_expanded_key_vaes


;;;       func            		core, ver, snum
slversion _XTS_AES_128_enc, 01,  04,  0071
slversion _XTS_AES_128_enc_expanded_key, 01,  04,  0072
slversion _XTS_AES_128_dec, 01,  04,  0073
slversion _XTS_AES_128_dec_expanded_key, 01,  04,  0074
