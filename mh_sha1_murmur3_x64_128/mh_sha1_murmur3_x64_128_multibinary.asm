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

%ifidn __OUTPUT_FORMAT__, elf32
 [bits 32]
%else
 default rel
 [bits 64]

 extern _mh_sha1_murmur3_x64_128_update_sse
 extern _mh_sha1_murmur3_x64_128_update_avx
 extern _mh_sha1_murmur3_x64_128_update_avx2
 extern _mh_sha1_murmur3_x64_128_finalize_sse
 extern _mh_sha1_murmur3_x64_128_finalize_avx
 extern _mh_sha1_murmur3_x64_128_finalize_avx2

 extern _mh_sha1_murmur3_x64_128_update_avx512
 extern _mh_sha1_murmur3_x64_128_finalize_avx512

%endif

extern _mh_sha1_murmur3_x64_128_update_base
extern _mh_sha1_murmur3_x64_128_finalize_base

mbin_interface _mh_sha1_murmur3_x64_128_update
mbin_interface _mh_sha1_murmur3_x64_128_finalize

%ifidn __OUTPUT_FORMAT__, elf64

 mbin_dispatch_init6 _mh_sha1_murmur3_x64_128_update, _mh_sha1_murmur3_x64_128_update_base, _mh_sha1_murmur3_x64_128_update_sse, _mh_sha1_murmur3_x64_128_update_avx, _mh_sha1_murmur3_x64_128_update_avx2, _mh_sha1_murmur3_x64_128_update_avx512
 mbin_dispatch_init6 _mh_sha1_murmur3_x64_128_finalize, _mh_sha1_murmur3_x64_128_finalize_base, _mh_sha1_murmur3_x64_128_finalize_sse, _mh_sha1_murmur3_x64_128_finalize_avx, _mh_sha1_murmur3_x64_128_finalize_avx2, _mh_sha1_murmur3_x64_128_finalize_avx512

%else
 mbin_dispatch_init2 _mh_sha1_murmur3_x64_128_update, _mh_sha1_murmur3_x64_128_update_base
 mbin_dispatch_init2 _mh_sha1_murmur3_x64_128_finalize, _mh_sha1_murmur3_x64_128_finalize_base
%endif

;;;       func                 				core, ver, snum
slversion _mh_sha1_murmur3_x64_128_update,		00, 02, 0252
slversion _mh_sha1_murmur3_x64_128_finalize,		00, 02, 0253
