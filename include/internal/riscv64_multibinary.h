/**********************************************************************
  Copyright (c) 2025 Institute of Software Chinese Academy of Sciences (ISCAS).

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of ISCAS nor the names of its
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
#ifndef __RISCV_MULTIBINARY_H__
#define __RISCV_MULTIBINARY_H__
#ifndef __riscv
#error "This file is for riscv only"
#endif

#ifdef __ASSEMBLY__

/**
 * # mbin_interface : the wrapper layer for isal-l api
 *
 * ## references:
 * * aarch64_multibinary.h
 * ## Usage:
 *
 * 	1. Define dispatcher function
 * 	2. name must be \name\()_dispatcher
 * 	3. Prototype should be *"void * \name\()_dispatcher"*
 * 	4. The dispatcher should return the right function pointer, revision and a string
 * 	5. The stack pointer sp must be 16-byte aligned under the standard RISC-V psABI. So we set aside 80 as multiple of 16-byte for stack alignment even we don't use all of them.
 * information .
 **/
.macro mbin_interface name:req
	.section .data
	.align 3
	.global \name\()_dispatcher_info
	.type \name\()_dispatcher_info, @object
\name\()_dispatcher_info:
	.quad \name\()_mbinit
	.section .text
	.global \name\()_mbinit
\name\()_mbinit:
	addi        sp, sp, -80
	sd          ra, 64(sp)
	sd          a0, 0(sp)
	sd          a1, 8(sp)
	sd          a2, 16(sp)
	sd          a3, 24(sp)
	sd          a4, 32(sp)
	sd          a5, 40(sp)
	sd          a6, 48(sp)
	sd          a7, 56(sp)
	call        \name\()_dispatcher
	mv          t2, a0
	la          t0, \name\()_dispatcher_info
	sd          a0, 0(t0)
	ld          ra, 64(sp)
	ld          a0, 0(sp)
	ld          a1, 8(sp)
	ld          a2, 16(sp)
	ld          a3, 24(sp)
	ld          a4, 32(sp)
	ld          a5, 40(sp)
	ld          a6, 48(sp)
	ld          a7, 56(sp)
	addi        sp, sp, 80
	jr          t2
.global \name\()
.type \name,%function
\name\():
	la          t0, \name\()_dispatcher_info
	ld          t1, 0(t0)
	jr          t1
.size \name,. - \name
.endm

/**
 * mbin_interface_base is used for the interfaces which have only
 * noarch implementation
 */
.macro mbin_interface_base name:req, base:req
	.extern \base
	.data
	.align 3
	.global \name\()_dispatcher_info
	.type \name\()_dispatcher_info, @object
\name\()_dispatcher_info:
	.dword \base
	.text
	.global \name
	.type \name, @function
\name:
	la      t0, \name\()_dispatcher_info
	ld      t0, (t0)
	jr      t0
.endm

#else /* __ASSEMBLY__ */

#include <sys/auxv.h>

#if defined(__has_include)
# if __has_include(<sys/hwprobe.h>)
#  include <sys/hwprobe.h>
#  define HAVE_RISCV_HWPROBE_HEADER 1
# endif
#endif

#ifndef HAVE_RISCV_HWPROBE_HEADER
#include <unistd.h>
#include <sys/syscall.h>
#endif

#ifndef HAVE_RVV
#define HAVE_RVV 0
#endif

#ifndef HAVE_RISCV_ZVK
#define HAVE_RISCV_ZVK 0
#endif

#define HWCAP_RV(letter) (1ul << ((letter) - 'A'))

/*
 * RISC-V multi-letter extension runtime detection via riscv_hwprobe.
 * AT_HWCAP only exposes coarse single-letter ISA bits such as V, so
 * fine-grained vector crypto dispatch has to query hwprobe.
 *
 * Usage:  riscv_hwprobe_ext(RISCV_HWPROBE_KEY_IMA_EXT_0,
 *                           RISCV_HWPROBE_EXT_ZVBB)
 */
#ifndef HAVE_RISCV_HWPROBE_HEADER
#ifndef __NR_riscv_hwprobe
#define __NR_riscv_hwprobe 258
#endif
struct riscv_hwprobe_pair {
        long long key;
        unsigned long long value;
};
#endif

#ifndef RISCV_HWPROBE_KEY_IMA_EXT_0
#define RISCV_HWPROBE_KEY_IMA_EXT_0 4
#endif
#ifndef RISCV_HWPROBE_EXT_ZBA
#define RISCV_HWPROBE_EXT_ZBA   (1ULL << 3)
#endif
#ifndef RISCV_HWPROBE_EXT_ZBB
#define RISCV_HWPROBE_EXT_ZBB   (1ULL << 4)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVBB
#define RISCV_HWPROBE_EXT_ZVBB  (1ULL << 17)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVBC
#define RISCV_HWPROBE_EXT_ZVBC  (1ULL << 18)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKB
#define RISCV_HWPROBE_EXT_ZVKB  (1ULL << 19)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKG
#define RISCV_HWPROBE_EXT_ZVKG  (1ULL << 20)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKNED
#define RISCV_HWPROBE_EXT_ZVKNED (1ULL << 21)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKNHA
#define RISCV_HWPROBE_EXT_ZVKNHA (1ULL << 22)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKNHB
#define RISCV_HWPROBE_EXT_ZVKNHB (1ULL << 23)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKSED
#define RISCV_HWPROBE_EXT_ZVKSED (1ULL << 24)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKSH
#define RISCV_HWPROBE_EXT_ZVKSH (1ULL << 25)
#endif
#ifndef RISCV_HWPROBE_EXT_ZVKT
#define RISCV_HWPROBE_EXT_ZVKT  (1ULL << 26)
#endif

static inline int riscv_hwprobe_ext(long long key, unsigned long long mask)
{
#ifdef HAVE_RISCV_HWPROBE_HEADER
        unsigned long long value = 0;

        if (__riscv_hwprobe_one(__riscv_hwprobe, key, &value) != 0)
                return 0;
        return (value & mask) == mask;
#else
        struct riscv_hwprobe_pair pairs[] = { { .key = key } };

        if (syscall(__NR_riscv_hwprobe, pairs, 1, 0, (void *)0, 0) == 0)
                return (pairs[0].value & mask) == mask;
        return 0;
#endif
}

static inline int riscv_has_rvv(void)
{
        return (getauxval(AT_HWCAP) & HWCAP_RV('V')) != 0;
}

static inline int is_zvk_aes_available(void)
{
#if HAVE_RISCV_ZVK
        return riscv_has_rvv() &&
               riscv_hwprobe_ext(RISCV_HWPROBE_KEY_IMA_EXT_0,
                                 RISCV_HWPROBE_EXT_ZVKB | RISCV_HWPROBE_EXT_ZVKNED |
                                         RISCV_HWPROBE_EXT_ZVKG);
#else
        return 0;
#endif
}

#define DEFINE_INTERFACE_DISPATCHER(name) void *name##_dispatcher(void)

#define PROVIDER_BASIC(name) PROVIDER_INFO(name##_base)

#define DO_DIGNOSTIC(x)     _Pragma GCC diagnostic ignored "-W"#x
#define DO_PRAGMA(x)        _Pragma(#x)
#define DIGNOSTIC_IGNORE(x) DO_PRAGMA(GCC diagnostic ignored #x)
#define DIGNOSTIC_PUSH()    DO_PRAGMA(GCC diagnostic push)
#define DIGNOSTIC_POP()     DO_PRAGMA(GCC diagnostic pop)

#define PROVIDER_INFO(_func_entry)                                                                 \
        ({      DIGNOSTIC_PUSH()                                                                   \
                DIGNOSTIC_IGNORE(-Wnested-externs)                                               \
                extern void _func_entry(void);                                                     \
                DIGNOSTIC_POP()                                                                    \
                _func_entry;                                                                       \
        })

#endif /* __ASSEMBLY__ */
#endif /* __RISCV_MULTIBINARY_H__ */
