;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2024 Intel Corporation All rights reserved.
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

default rel

%define SELF_TEST_DONE_AND_OK   0x0 ; Same value as success for internal self tests
%define SELF_TEST_DONE_AND_FAIL 0x1 ; Same value as failure for internal self tests
%define SELF_TEST_NOT_DONE      0x2
%define SELF_TEST_RUNNING       0x3

section .data
align 16

self_test_status:
dd      SELF_TEST_NOT_DONE

section .text

%ifidn __OUTPUT_FORMAT__, elf64
	%xdefine arg1 edi
%else
	%xdefine arg1 ecx
%endif

;
; Returns self tests status and sets internal atomic status to SELF_TEST_RUNNING,
; if the self tests have not been run yet.
;
; Returns 0 if self tests were successful
; Returns 1 if self tests fail
; Returns 3 if self tests not done yet
align 32
mk_global asm_check_self_tests_status, function
asm_check_self_tests_status:
        mov     eax, [self_test_status]
        ; Check if self tests are done (SELF_TEST_DONE_AND_OK or SELF_TEST_DONE_AND_FAIL, so 0 or 1)
        test    eax, 0x2
        jnz     check_self_test_not_done

        ; Returns 0 or 1
        ret

check_self_test_not_done:
        ; At this stage, the self tests either have not been run or they are being run by another thread
        mov     eax, SELF_TEST_NOT_DONE

        mov     edx, SELF_TEST_RUNNING
        ; If self tests status == SELF_TEST_NOT_DONE (in eax),
        ; change self tests status = SELF_TEST_RUNNING
        lock cmpxchg dword [self_test_status], edx
        jz      return

        ; At this stage, some other thread has started running the tests, so loop until it changes
check_status_loop:
        pause
        cmp     dword [self_test_status], SELF_TEST_RUNNING
        je      check_status_loop

        ; Read value set by the other thread and return it
        mov     eax, [self_test_status]
return:
        ret


align 32
mk_global asm_set_self_tests_status, function
asm_set_self_tests_status:
        ; Set self tests status
        mov     dword [self_test_status], arg1 ; Either 0 (SELF_TEST_DONE_AND_OK) or 1 (SELF_TEST_DONE_AND_FAIL)
        ret
