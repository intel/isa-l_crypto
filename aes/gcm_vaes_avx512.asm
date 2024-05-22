;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2018-2022, Intel Corporation All rights reserved.
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
%include "include/gcm_vaes_avx512.inc"

%ifndef FUNCT_EXTENSION
%define FUNCT_EXTENSION
%endif

;; Define new macros that add NT to the function name
%undef FN_NAME

%ifdef GCM128_MODE
%define FN_NAME(x,y) _aes_gcm_ %+ x %+ _128 %+ y %+ vaes_avx512 %+ FUNCT_EXTENSION
%endif

%ifdef GCM192_MODE
%define FN_NAME(x,y) _aes_gcm_ %+ x %+ _192 %+ y %+ vaes_avx512 %+ FUNCT_EXTENSION
%endif

%ifdef GCM256_MODE
%define FN_NAME(x,y) _aes_gcm_ %+ x %+ _256 %+ y %+ vaes_avx512 %+ FUNCT_EXTENSION
%endif

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_precomp_128_vaes_avx512 /
;       _aes_gcm_precomp_192_vaes_avx512 /
;       _aes_gcm_precomp_256_vaes_avx512
;       (struct isal_gcm_key_data *key_data)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifnidn FUNCT_EXTENSION, _nt
global FN_NAME(precomp,_)
FN_NAME(precomp,_):
        endbranch
        FUNC_SAVE small_frame

        vpxor   xmm6, xmm6
        ENCRYPT_SINGLE_BLOCK    arg1, xmm6              ; xmm6 = HashKey

        vpshufb  xmm6, [rel SHUF_MASK]
        ;;;;;;;;;;;;;;;  PRECOMPUTATION of HashKey<<1 mod poly from the HashKey;;;;;;;;;;;;;;;
        vmovdqa  xmm2, xmm6
        vpsllq   xmm6, xmm6, 1
        vpsrlq   xmm2, xmm2, 63
        vmovdqa  xmm1, xmm2
        vpslldq  xmm2, xmm2, 8
        vpsrldq  xmm1, xmm1, 8
        vpor     xmm6, xmm6, xmm2
        ;reduction
        vpshufd  xmm2, xmm1, 00100100b
        vpcmpeqd xmm2, [rel TWOONE]
        vpand    xmm2, xmm2, [rel POLY]
        vpxor    xmm6, xmm6, xmm2                       ; xmm6 holds the HashKey<<1 mod poly
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu  [arg1 + HashKey_1], xmm6                 ; store HashKey<<1 mod poly

        PRECOMPUTE arg1, xmm6, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm7, xmm8

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
exit_precomp:

        ret

%endif	; _nt

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_init_128_vaes_avx512 / _aes_gcm_init_192_vaes_avx512 / _aes_gcm_init_256_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifnidn FUNCT_EXTENSION, _nt
global FN_NAME(init,_)
FN_NAME(init,_):
        endbranch
        FUNC_SAVE small_frame

        GCM_INIT arg1, arg2, arg3, arg4, arg5, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, multi_call

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

%endif	; _nt

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_enc_128_update_vaes_avx512 / _aes_gcm_enc_192_update_vaes_avx512 /
;       _aes_gcm_enc_256_update_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global FN_NAME(enc,_update_)
FN_NAME(enc,_update_):
        endbranch
        FUNC_SAVE

        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, ENC, multi_call

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_dec_128_update_vaes_avx512 / _aes_gcm_dec_192_update_vaes_avx512 /
;       _aes_gcm_dec_256_update_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global FN_NAME(dec,_update_)
FN_NAME(dec,_update_):
        endbranch
        FUNC_SAVE

        GCM_ENC_DEC arg1, arg2, arg3, arg4, arg5, DEC, multi_call

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_enc_128_finalize_vaes_avx512 / _aes_gcm_enc_192_finalize_vaes_avx512 /
;       _aes_gcm_enc_256_finalize_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifnidn FUNCT_EXTENSION, _nt
global FN_NAME(enc,_finalize_)
FN_NAME(enc,_finalize_):
        endbranch
        FUNC_SAVE small_frame
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

%endif	; _nt

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_dec_128_finalize_vaes_avx512 / _aes_gcm_dec_192_finalize_vaes_avx512
;       _aes_gcm_dec_256_finalize_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%ifnidn FUNCT_EXTENSION, _nt
global FN_NAME(dec,_finalize_)
FN_NAME(dec,_finalize_):
        endbranch

        FUNC_SAVE small_frame
        GCM_COMPLETE    arg1, arg2, arg3, arg4, multi_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

%endif	; _nt

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_enc_128_vaes_avx512 / _aes_gcm_enc_192_vaes_avx512 / _aes_gcm_enc_256_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global FN_NAME(enc,_)
FN_NAME(enc,_):
        endbranch
        FUNC_SAVE

        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, ENC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;void   _aes_gcm_dec_128_vaes_avx512 / _aes_gcm_dec_192_vaes_avx512 / _aes_gcm_dec_256_vaes_avx512
;       (const struct isal_gcm_key_data *key_data,
;        struct isal_gcm_context_data *context_data,
;        u8       *out,
;        const u8 *in,
;        u64      msg_len,
;        u8       *iv,
;        const u8 *aad,
;        u64      aad_len,
;        u8       *auth_tag,
;        u64      auth_tag_len);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global FN_NAME(dec,_)
FN_NAME(dec,_):
        endbranch
        FUNC_SAVE

        GCM_INIT arg1, arg2, arg6, arg7, arg8, r10, r11, r12, k1, xmm14, xmm2, \
                zmm1, zmm3, zmm4, zmm5, zmm6, zmm7, zmm8, zmm9, zmm10, zmm11, \
                zmm12, zmm13, zmm15, zmm16, zmm17, zmm18, zmm19, zmm20, single_call
        GCM_ENC_DEC  arg1, arg2, arg3, arg4, arg5, DEC, single_call
        GCM_COMPLETE arg1, arg2, arg9, arg10, single_call, k1, r10, r11, r12

%ifdef SAFE_DATA
        clear_scratch_zmms_asm
%endif ;; SAFE_DATA
        FUNC_RESTORE
        ret
