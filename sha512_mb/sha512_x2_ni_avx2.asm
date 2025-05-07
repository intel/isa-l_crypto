;;
;; Copyright (c) 2024, Intel Corporation
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions are met:
;;
;;     * Redistributions of source code must retain the above copyright notice,
;;       this list of conditions and the following disclaimer.
;;     * Redistributions in binary form must reproduce the above copyright
;;       notice, this list of conditions and the following disclaimer in the
;;       documentation and/or other materials provided with the distribution.
;;     * Neither the name of Intel Corporation nor the names of its contributors
;;       may be used to endorse or promote products derived from this software
;;       without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
;; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
;; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
;; OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;

;; ===========================================================
;; NOTE about comment format:
;;
;;      ymm = a b c d
;;           ^       ^
;;           |       |
;;      MSB--+       +--LSB
;;
;;      a - most significant word in `ymm`
;;      d - least significant word in `ymm`
;; ===========================================================

%use smartalign

%include "include/os.inc"
%include "include/clear_regs.inc"
%include "sha512_mb_mgr_datastruct.asm"

%include "reg_sizes.asm"

; resdq = res0 => 16 bytes
struc frame
.ABEF_SAVE      resy    1
.CDGH_SAVE      resy    1
.ABEF_SAVEb     resy    1
.CDGH_SAVEb     resy    1
endstruc

%ifdef LINUX
%define arg1    rdi
%define arg2    rsi
%define arg3    rdx
%define arg4    rcx
%else
%define arg1    rcx
%define arg2    rdx
%define arg3    r8
%define arg4    r9
%endif

%define args            arg1
%define NUM_BLKS        arg2

%define INP             arg3
%define INPb            arg4

%define SHA512_CONSTS   rax

%define MSG             ymm0
%define STATE0          ymm1
%define STATE1          ymm2
%define MSGTMP0         ymm3
%define MSGTMP1         ymm4
%define MSGTMP2         ymm5

%define YTMP0           ymm6
%define YTMP1           ymm7

%define STATE0b         ymm8
%define STATE1b         ymm9
%define MSGb            ymm10

%define YTMP2           ymm11
%define YTMP3           ymm12

%define MSGTMP0b        ymm13
%define MSGTMP1b        ymm14
%define MSGTMP2b        ymm15

%define GP_STORAGE      6*8
%ifndef LINUX
%define XMM_STORAGE     10*16
%else
%define XMM_STORAGE     0
%endif

%define VARIABLE_OFFSET XMM_STORAGE + GP_STORAGE
%define GP_OFFSET XMM_STORAGE

%macro SHA512ROUNDS4_X2 13
%define %%Y0            %1      ;; MSG
%define %%Y1            %2      ;; STATE0
%define %%Y2            %3      ;; STATE1
%define %%Y3            %4      ;; TMP
%define %%Y4            %5      ;; TMP MSG
%define %%Y6            %6      ;; TMP MSG
%define %%_Y0           %7      ;; MSGb
%define %%_Y1           %8      ;; STATE0b
%define %%_Y2           %9      ;; STATE1b
%define %%_Y3           %10     ;; TMP
%define %%_Y4           %11     ;; TMP MSGb
%define %%_Y6           %12     ;; TMP MSGb
%define %%I             %13     ;; IDX

        vpaddq          %%Y0, %%Y3, [SHA512_CONSTS+32*%%I]
        vpermq          YTMP1, %%Y6, 0x39
        vpermq          YTMP3, %%Y3, 0x1b
        vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
        vpaddq          %%Y4, %%Y4, YTMP1
                vpaddq          %%_Y0, %%_Y3, [SHA512_CONSTS+32*%%I]
                vpermq          YTMP1, %%_Y6, 0x39
                vpermq          YTMP3, %%_Y3, 0x1b
                vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
                vpaddq          %%_Y4, %%_Y4, YTMP1
        vsha512rnds2    %%Y2, %%Y1, XWORD(%%Y0)
        vperm2i128      %%Y0, %%Y0, %%Y0, 0x01
                vsha512rnds2    %%_Y2, %%_Y1, XWORD(%%_Y0)
                vperm2i128      %%_Y0, %%_Y0, %%_Y0, 0x01
        vsha512msg2     %%Y4, %%Y3
        vsha512rnds2    %%Y1, %%Y2, XWORD(%%Y0)
                vsha512msg2     %%_Y4, %%_Y3
                vsha512rnds2    %%_Y1, %%_Y2, XWORD(%%_Y0)
        vsha512msg1     %%Y6, XWORD(%%Y3)
                vsha512msg1     %%_Y6, XWORD(%%_Y3)
%endmacro

%macro SHA512ROUNDS4_FINAL_X2 13
%define %%Y0            %1      ;; MSG
%define %%Y1            %2      ;; STATE0
%define %%Y2            %3      ;; STATE1
%define %%Y3            %4      ;; TMP
%define %%Y4            %5      ;; TMP MSG
%define %%Y6            %6      ;; TMP MSG
%define %%_Y0           %7      ;; MSGb
%define %%_Y1           %8      ;; STATE0b
%define %%_Y2           %9      ;; STATE1b
%define %%_Y3           %10     ;; TMP
%define %%_Y4           %11     ;; TMP MSGb
%define %%_Y6           %12     ;; TMP MSGb
%define %%I             %13     ;; IDX

        vpaddq          %%Y0, %%Y3, [SHA512_CONSTS+32*%%I]
        vpermq          YTMP3, %%Y3, 0x1b
        vpermq          YTMP1, %%Y6, 0x39
        vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
        vpaddq          %%Y4, %%Y4, YTMP1
                vpaddq          %%_Y0, %%_Y3, [SHA512_CONSTS+32*%%I]
                vpermq          YTMP3, %%_Y3, 0x1b
                vpermq          YTMP1, %%_Y6, 0x39
                vpblendd        YTMP1, YTMP3, YTMP1, 0x3f
                vpaddq          %%_Y4, %%_Y4, YTMP1
        vsha512rnds2    %%Y2, %%Y1, XWORD(%%Y0)
        vperm2i128      %%Y0, %%Y0, %%Y0, 0x01
                vsha512rnds2    %%_Y2, %%_Y1, XWORD(%%_Y0)
                vperm2i128      %%_Y0, %%_Y0, %%Y0, 0x01
        vsha512rnds2    %%Y1, %%Y2, XWORD(%%Y0)
        vsha512msg2     %%Y4, %%Y3
                vsha512rnds2    %%_Y1, %%_Y2, XWORD(%%_Y0)
                vsha512msg2     %%_Y4, %%_Y3
%endmacro

mksection .rodata
default rel
;; re-use symbols from AVX codebase
align 64
SHA512_K_AVX:
       dq      0x428a2f98d728ae22,0x7137449123ef65cd
       dq      0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
       dq      0x3956c25bf348b538,0x59f111f1b605d019
       dq      0x923f82a4af194f9b,0xab1c5ed5da6d8118
       dq      0xd807aa98a3030242,0x12835b0145706fbe
       dq      0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
       dq      0x72be5d74f27b896f,0x80deb1fe3b1696b1
       dq      0x9bdc06a725c71235,0xc19bf174cf692694
       dq      0xe49b69c19ef14ad2,0xefbe4786384f25e3
       dq      0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
       dq      0x2de92c6f592b0275,0x4a7484aa6ea6e483
       dq      0x5cb0a9dcbd41fbd4,0x76f988da831153b5
       dq      0x983e5152ee66dfab,0xa831c66d2db43210
       dq      0xb00327c898fb213f,0xbf597fc7beef0ee4
       dq      0xc6e00bf33da88fc2,0xd5a79147930aa725
       dq      0x06ca6351e003826f,0x142929670a0e6e70
       dq      0x27b70a8546d22ffc,0x2e1b21385c26c926
       dq      0x4d2c6dfc5ac42aed,0x53380d139d95b3df
       dq      0x650a73548baf63de,0x766a0abb3c77b2a8
       dq      0x81c2c92e47edaee6,0x92722c851482353b
       dq      0xa2bfe8a14cf10364,0xa81a664bbc423001
       dq      0xc24b8b70d0f89791,0xc76c51a30654be30
       dq      0xd192e819d6ef5218,0xd69906245565a910
       dq      0xf40e35855771202a,0x106aa07032bbd1b8
       dq      0x19a4c116b8d2d0c8,0x1e376c085141ab53
       dq      0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
       dq      0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
       dq      0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
       dq      0x748f82ee5defb2fc,0x78a5636f43172f60
       dq      0x84c87814a1f0ab72,0x8cc702081a6439ec
       dq      0x90befffa23631e28,0xa4506cebde82bde9
       dq      0xbef9a3f7b2c67915,0xc67178f2e372532b
       dq      0xca273eceea26619c,0xd186b8c721c0c207
       dq      0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
       dq      0x06f067aa72176fba,0x0a637dc5a2c898a6
       dq      0x113f9804bef90dae,0x1b710b35131c471b
       dq      0x28db77f523047d84,0x32caab7b40c72493
       dq      0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
       dq      0x4cc5d4becb3e42b6,0x597f299cfc657e2a
       dq      0x5fcb6fab3ad6faec,0x6c44198c4a475817

align 32
SHUF_MASK:
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f
        dq 0x0001020304050607, 0x08090a0b0c0d0e0f

mksection .text
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; void sha512_ni_x2_avx2(SHA512_ARGS *args, UINT64 size_in_blocks)
;; arg1 : pointer to args
;; arg2 : size (in blocks) ;; assumed to be >= 1
align 32
MKGLOBAL(sha512_ni_x2_avx2,function,internal)
sha512_ni_x2_avx2:
        mov             r11, rsp
        sub             rsp, frame_size
        and             rsp, -32

        or              NUM_BLKS, NUM_BLKS
        je              .done_hash

        ;; load input pointers
        mov             INP, [args + _args_data_ptr + 0*8]
        mov             INPb, [args + _args_data_ptr + 1*8]

        ;; load constants pointer
        lea             SHA512_CONSTS, [rel SHA512_K_AVX]

        ;; load current hash value and transform
        vmovdqu         STATE0, [args + _args_digest + 0*64]
        vmovdqu         STATE1, [args + _args_digest + 0*64 + 32]
                vmovdqu         STATE0b, [args + _args_digest + 1*64]
                vmovdqu         STATE1b, [args + _args_digest + 1*64 + 32]

        vperm2i128 YTMP1, STATE0, STATE1, 0x20
                    vperm2i128 YTMP0, STATE0b, STATE1b, 0x20
        vperm2i128 STATE1, STATE0, STATE1, 0x31
                    vperm2i128 STATE1b, STATE0b, STATE1b, 0x31
        vpermq STATE0, YTMP1, 0x1b
                    vpermq STATE0b, YTMP0, 0x1b
        vpermq STATE1, STATE1, 0x1b
                    vpermq STATE1b, STATE1b, 0x1b

align 32
.block_loop:
        ;; Save digests
        vmovdqa         [rsp + frame.ABEF_SAVE], STATE0
        vmovdqa         [rsp + frame.CDGH_SAVE], STATE1
                vmovdqa         [rsp + frame.ABEF_SAVEb], STATE0b
                vmovdqa         [rsp + frame.CDGH_SAVEb], STATE1b

        ;; R0- R3
        vmovdqu MSG, [INP+32*0]
                    vmovdqu MSGb, [INPb+32*0]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP0, MSG
                    vmovdqu MSGTMP0b, MSGb
        vpaddq MSG, MSG, [SHA512_CONSTS+32*0]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*0]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)

        ;; R4-7
        vmovdqu MSG, [INP+32*1]
                    vmovdqu MSGb, [INPb+32*1]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP1, MSG
                    vmovdqu MSGTMP1b, MSGb
        vpaddq MSG, MSG, [SHA512_CONSTS+32*1]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*1]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)
        vsha512msg1 MSGTMP0, XWORD(MSGTMP1)
                    vsha512msg1 MSGTMP0b, XWORD(MSGTMP1b)

        ;; R8-R11
        vmovdqu MSG, [INP+32*2]
                    vmovdqu MSGb, [INPb+32*2]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu MSGTMP2, MSG
                    vmovdqu MSGTMP2b, MSGb


        vpaddq MSG, MSG, [SHA512_CONSTS+32*2]
                    vpaddq MSGb, MSGb, [SHA512_CONSTS+32*2]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)
        vsha512msg1 MSGTMP1, XWORD(MSGTMP2)
                    vsha512msg1 MSGTMP1b, XWORD(MSGTMP2b)

        ;; R12-15
        vmovdqu MSG, [INP+32*3]
                    vmovdqu MSGb, [INPb+32*3]
        vpshufb MSG, MSG, [SHUF_MASK]
                    vpshufb MSGb, MSGb, [SHUF_MASK]
        vmovdqu YTMP0, MSG
                    vmovdqu YTMP2, MSGb

        ;; R16-75
        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, \
                MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 3

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 4

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 5

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, \
                MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 6

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, \
                MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 7

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 8

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 9

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, \
                MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 10

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, \
                MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 11

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 12

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 13

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, \
                MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 14

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, YTMP0, MSGTMP0, MSGTMP2, \
                MSGb, STATE0b, STATE1b, YTMP2, MSGTMP0b, MSGTMP2b, 15

        SHA512ROUNDS4_X2 MSG, STATE0, STATE1, MSGTMP0, MSGTMP1, YTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP0b, MSGTMP1b, YTMP2, 16

        SHA512ROUNDS4_FINAL_X2 MSG, STATE0, STATE1, MSGTMP1, MSGTMP2, MSGTMP0, \
                MSGb, STATE0b, STATE1b, MSGTMP1b, MSGTMP2b, MSGTMP0b, 17

        SHA512ROUNDS4_FINAL_X2 MSG, STATE0, STATE1, MSGTMP2, YTMP0, MSGTMP1, \
                MSGb, STATE0b, STATE1b, MSGTMP2b, YTMP2, MSGTMP1b, 18

        ;; R76-79
        vpaddq MSG, YTMP0, [SHA512_CONSTS+32*19]
                    vpaddq MSGb, YTMP2, [SHA512_CONSTS+32*19]
        vsha512rnds2 STATE1, STATE0, XWORD(MSG)
                    vsha512rnds2 STATE1b, STATE0b, XWORD(MSGb)
        vperm2i128 MSG, MSG, MSG, 0x01
                    vperm2i128 MSGb, MSGb, MSGb, 0x01
        vsha512rnds2 STATE0, STATE1, XWORD(MSG)
                    vsha512rnds2 STATE0b, STATE1b, XWORD(MSGb)

        vpaddq STATE0, STATE0, [rsp + frame.ABEF_SAVE]
        vpaddq STATE1, STATE1, [rsp + frame.CDGH_SAVE]
                    vpaddq STATE0b, STATE0b, [rsp + frame.ABEF_SAVEb]
                    vpaddq STATE1b, STATE1b, [rsp + frame.CDGH_SAVEb]

        lea INP, [INP+128]
                    lea INPb, [INPb+128]

        dec     NUM_BLKS
        jne     .block_loop

        ;; Update input pointers
        mov     [args + _args_data_ptr + 0*8], INP
        mov     [args + _args_data_ptr + 1*8], INPb

        ; Reorder and write back the hash value
        vperm2i128 MSGTMP0, STATE0, STATE1, 0x31
                    vperm2i128 MSGTMP1, STATE0b, STATE1b, 0x31
        vperm2i128 MSGTMP2, STATE0, STATE1, 0x20
                    vperm2i128 YTMP0, STATE0b, STATE1b, 0x20
        vpermq STATE0, MSGTMP0, 0xb1
        vpermq STATE1, MSGTMP2, 0xb1
                    vpermq STATE0b, MSGTMP1, 0xb1
                    vpermq STATE1b, YTMP0, 0xb1

        ;; update digests
        vmovdqu         [args + _args_digest + 0*64], STATE0
        vmovdqu         [args + _args_digest + 0*64 + 32], STATE1
                vmovdqu         [args + _args_digest + 1*64], STATE0b
                vmovdqu         [args + _args_digest + 1*64 + 32], STATE1b

        vzeroupper

%ifdef SAFE_DATA
        vpxor           YTMP0, YTMP0
        vmovdqa         [rsp + frame.ABEF_SAVE], YTMP0
        vmovdqa         [rsp + frame.CDGH_SAVE], YTMP0
        vmovdqa         [rsp + frame.ABEF_SAVEb], YTMP0
        vmovdqa         [rsp + frame.CDGH_SAVEb], YTMP0
%endif

align 32
.done_hash:
        mov     rsp, r11
        ret

mksection stack-noexec
