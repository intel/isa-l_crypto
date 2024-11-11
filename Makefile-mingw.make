########################################################################
#  Copyright(c) 2011-2024 Intel Corporation All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  SPDX-License-Identifier: BSD-3-Clause
########################################################################

# This file can be auto-regenerated with $make -f Makefile.unx Makefile.nmake

objs = \
    bin/sha1_ctx_sse.o \
    bin/sha1_ctx_avx.o \
    bin/sha1_ctx_avx2.o \
    bin/sha1_ctx_base.o \
    bin/sha1_mb_mgr_init_sse.o \
    bin/sha1_mb_mgr_init_avx2.o \
    bin/sha1_mb_mgr_submit_sse.o \
    bin/sha1_mb_mgr_submit_avx.o \
    bin/sha1_mb_mgr_submit_avx2.o \
    bin/sha1_mb_mgr_flush_sse.o \
    bin/sha1_mb_mgr_flush_avx.o \
    bin/sha1_mb_mgr_flush_avx2.o \
    bin/sha1_mb_x4_sse.o \
    bin/sha1_mb_x4_avx.o \
    bin/sha1_mb_x8_avx2.o \
    bin/sha1_multibinary.o \
    bin/sha1_ctx_avx512.o \
    bin/sha1_mb_mgr_init_avx512.o \
    bin/sha1_mb_mgr_submit_avx512.o \
    bin/sha1_mb_mgr_flush_avx512.o \
    bin/sha1_mb_x16_avx512.o \
    bin/sha1_opt_x1.o \
    bin/sha1_ni_x1.o \
    bin/sha1_ni_x2.o \
    bin/sha1_ctx_sse_ni.o \
    bin/sha1_ctx_avx512_ni.o \
    bin/sha1_mb_mgr_submit_sse_ni.o \
    bin/sha1_mb_mgr_flush_sse_ni.o \
    bin/sha1_mb_mgr_flush_avx512_ni.o \
    bin/sha256_ctx_sse.o \
    bin/sha256_ctx_avx.o \
    bin/sha256_ctx_avx2.o \
    bin/sha256_ctx_base.o \
    bin/sha256_mb_mgr_init_sse.o \
    bin/sha256_mb_mgr_init_avx2.o \
    bin/sha256_mb_mgr_submit_sse.o \
    bin/sha256_mb_mgr_submit_avx.o \
    bin/sha256_mb_mgr_submit_avx2.o \
    bin/sha256_mb_mgr_flush_sse.o \
    bin/sha256_mb_mgr_flush_avx.o \
    bin/sha256_mb_mgr_flush_avx2.o \
    bin/sha256_mb_x4_sse.o \
    bin/sha256_mb_x4_avx.o \
    bin/sha256_mb_x8_avx2.o \
    bin/sha256_multibinary.o \
    bin/sha256_ctx_avx512.o \
    bin/sha256_mb_mgr_init_avx512.o \
    bin/sha256_mb_mgr_submit_avx512.o \
    bin/sha256_mb_mgr_flush_avx512.o \
    bin/sha256_mb_x16_avx512.o \
    bin/sha256_opt_x1.o \
    bin/sha256_ni_x1.o \
    bin/sha256_ni_x2.o \
    bin/sha256_ctx_sse_ni.o \
    bin/sha256_ctx_avx512_ni.o \
    bin/sha256_mb_mgr_submit_sse_ni.o \
    bin/sha256_mb_mgr_flush_sse_ni.o \
    bin/sha256_mb_mgr_flush_avx512_ni.o \
    bin/sha512_ctx_sse.o \
    bin/sha512_ctx_avx.o \
    bin/sha512_ctx_avx2.o \
    bin/sha512_ctx_sb_sse4.o \
    bin/sha512_ctx_base.o \
    bin/sha512_mb_mgr_init_sse.o \
    bin/sha512_mb_mgr_init_avx2.o \
    bin/sha512_sb_mgr_init_sse4.o \
    bin/sha512_mb_mgr_submit_sse.o \
    bin/sha512_mb_mgr_submit_avx.o \
    bin/sha512_mb_mgr_submit_avx2.o \
    bin/sha512_mb_mgr_flush_sse.o \
    bin/sha512_mb_mgr_flush_avx.o \
    bin/sha512_mb_mgr_flush_avx2.o \
    bin/sha512_mb_x2_sse.o \
    bin/sha512_mb_x2_avx.o \
    bin/sha512_mb_x4_avx2.o \
    bin/sha512_multibinary.o \
    bin/sha512_sb_mgr_submit_sse4.o \
    bin/sha512_sb_mgr_flush_sse4.o \
    bin/sha512_sse4.o \
    bin/sha512_ctx_avx512.o \
    bin/sha512_mb_mgr_init_avx512.o \
    bin/sha512_mb_mgr_submit_avx512.o \
    bin/sha512_mb_mgr_flush_avx512.o \
    bin/sha512_mb_x8_avx512.o \
    bin/md5_ctx_sse.o \
    bin/md5_ctx_avx.o \
    bin/md5_ctx_avx2.o \
    bin/md5_ctx_base.o \
    bin/md5_mb_mgr_init_sse.o \
    bin/md5_mb_mgr_init_avx2.o \
    bin/md5_mb_mgr_init_avx512.o \
    bin/md5_mb_mgr_submit_sse.o \
    bin/md5_mb_mgr_submit_avx.o \
    bin/md5_mb_mgr_submit_avx2.o \
    bin/md5_mb_mgr_flush_sse.o \
    bin/md5_mb_mgr_flush_avx.o \
    bin/md5_mb_mgr_flush_avx2.o \
    bin/md5_mb_x4x2_sse.o \
    bin/md5_mb_x4x2_avx.o \
    bin/md5_mb_x8x2_avx2.o \
    bin/md5_multibinary.o \
    bin/md5_mb_mgr_submit_avx512.o \
    bin/md5_mb_mgr_flush_avx512.o \
    bin/md5_mb_x16x2_avx512.o \
    bin/md5_ctx_avx512.o \
    bin/mh_sha1_block_base.o \
    bin/mh_sha1_finalize_base.o \
    bin/mh_sha1_update_base.o \
    bin/sha1_for_mh_sha1.o \
    bin/mh_sha1.o \
    bin/mh_sha1_multibinary.o \
    bin/mh_sha1_block_sse.o \
    bin/mh_sha1_block_avx.o \
    bin/mh_sha1_block_avx2.o \
    bin/mh_sha1_block_avx512.o \
    bin/mh_sha1_avx512.o \
    bin/murmur3_x64_128_internal.o \
    bin/mh_sha1_murmur3_x64_128.o \
    bin/mh_sha1_murmur3_x64_128_finalize_base.o \
    bin/mh_sha1_murmur3_x64_128_update_base.o \
    bin/mh_sha1_murmur3_x64_128_block_sse.o \
    bin/mh_sha1_murmur3_x64_128_block_avx.o \
    bin/mh_sha1_murmur3_x64_128_block_avx2.o \
    bin/mh_sha1_murmur3_x64_128_multibinary.o \
    bin/mh_sha1_murmur3_x64_128_avx512.o \
    bin/mh_sha1_murmur3_x64_128_block_avx512.o \
    bin/sha256_for_mh_sha256.o \
    bin/mh_sha256.o \
    bin/mh_sha256_block_sse.o \
    bin/mh_sha256_block_avx.o \
    bin/mh_sha256_block_avx2.o \
    bin/mh_sha256_multibinary.o \
    bin/mh_sha256_finalize_base.o \
    bin/mh_sha256_update_base.o \
    bin/mh_sha256_block_base.o \
    bin/mh_sha256_block_avx512.o \
    bin/mh_sha256_avx512.o \
    bin/rolling_hashx_base.o \
    bin/rolling_hash2.o \
    bin/rolling_hash2_until_04.o \
    bin/rolling_hash2_until_00.o \
    bin/rolling_hash2_multibinary.o \
    bin/sm3_ctx_base.o \
    bin/sm3_multibinary.o \
    bin/sm3_ctx_avx512.o \
    bin/sm3_mb_mgr_submit_avx512.o \
    bin/sm3_mb_mgr_flush_avx512.o \
    bin/sm3_mb_x16_avx512.o \
    bin/sm3_ctx_avx2.o \
    bin/sm3_mb_mgr_submit_avx2.o \
    bin/sm3_mb_mgr_flush_avx2.o \
    bin/sm3_mb_x8_avx2.o \
    bin/gcm_multibinary.o \
    bin/gcm_pre.o \
    bin/gcm128_avx_gen2.o \
    bin/gcm128_avx_gen4.o \
    bin/gcm128_sse.o \
    bin/gcm256_avx_gen2.o \
    bin/gcm256_avx_gen4.o \
    bin/gcm256_sse.o \
    bin/gcm128_vaes_avx512.o \
    bin/gcm256_vaes_avx512.o \
    bin/gcm128_avx_gen2_nt.o \
    bin/gcm128_avx_gen4_nt.o \
    bin/gcm128_sse_nt.o \
    bin/gcm256_avx_gen2_nt.o \
    bin/gcm256_avx_gen4_nt.o \
    bin/gcm256_sse_nt.o \
    bin/gcm128_vaes_avx512_nt.o \
    bin/gcm256_vaes_avx512_nt.o \
    bin/gcm_multibinary_nt.o \
    bin/keyexp_multibinary.o \
    bin/keyexp_128.o \
    bin/keyexp_192.o \
    bin/keyexp_256.o \
    bin/cbc_multibinary.o \
    bin/cbc_dec_128_x4_sse.o \
    bin/cbc_dec_128_x8_avx.o \
    bin/cbc_dec_192_x4_sse.o \
    bin/cbc_dec_192_x8_avx.o \
    bin/cbc_dec_256_x4_sse.o \
    bin/cbc_dec_256_x8_avx.o \
    bin/cbc_enc_128_x4_sb.o \
    bin/cbc_enc_128_x8_sb.o \
    bin/cbc_enc_192_x4_sb.o \
    bin/cbc_enc_192_x8_sb.o \
    bin/cbc_enc_256_x4_sb.o \
    bin/cbc_enc_256_x8_sb.o \
    bin/cbc_dec_vaes_avx512.o \
    bin/cbc_pre.o \
    bin/xts_aes_128_multibinary.o \
    bin/XTS_AES_128_dec_sse.o \
    bin/XTS_AES_128_dec_expanded_key_sse.o \
    bin/XTS_AES_128_enc_sse.o \
    bin/XTS_AES_128_enc_expanded_key_sse.o \
    bin/XTS_AES_128_dec_avx.o \
    bin/XTS_AES_128_dec_expanded_key_avx.o \
    bin/XTS_AES_128_enc_avx.o \
    bin/XTS_AES_128_enc_expanded_key_avx.o \
    bin/xts_aes_256_multibinary.o \
    bin/XTS_AES_256_dec_avx.o \
    bin/XTS_AES_256_dec_expanded_key_avx.o \
    bin/XTS_AES_256_enc_avx.o \
    bin/XTS_AES_256_enc_expanded_key_avx.o \
    bin/XTS_AES_256_dec_sse.o \
    bin/XTS_AES_256_dec_expanded_key_sse.o \
    bin/XTS_AES_256_enc_sse.o \
    bin/XTS_AES_256_enc_expanded_key_sse.o \
    bin/XTS_AES_256_enc_vaes.o \
    bin/XTS_AES_128_enc_vaes.o \
    bin/XTS_AES_256_enc_expanded_key_vaes.o \
    bin/XTS_AES_128_enc_expanded_key_vaes.o \
    bin/XTS_AES_256_dec_vaes.o \
    bin/XTS_AES_128_dec_vaes.o \
    bin/XTS_AES_256_dec_expanded_key_vaes.o \
    bin/XTS_AES_128_dec_expanded_key_vaes.o \
    bin/aes_keyexp.o

INCLUDES  = -I./ -Isha1_mb/ -Isha256_mb/ -Isha512_mb/ -Imd5_mb/ -Imh_sha1/ -Imh_sha1_murmur3_x64_128/ -Imh_sha256/ -Irolling_hash/ -Ism3_mb/ -Iaes/ -Iinclude/
# Modern asm feature level, consider upgrading nasm/yasm before decreasing feature_level
FEAT_FLAGS = -DHAVE_AS_KNOWS_AVX512 -DAS_FEATURE_LEVEL=10 -DHAVE_AS_KNOWS_SHANI
CFLAGS_REL = -O2 -DNDEBUG
CFLAGS_DBG = -O0 -g -DDEBUG
LINKFLAGS  = -Wl,--gc-sections
CFLAGS     = $(CFLAGS_REL) -g -Wall -Wchar-subscripts -Wformat-security -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wundef -fno-common -fno-strict-aliasing -fPIC $(FEAT_FLAGS) $(INCLUDES) $(D)
ASFLAGS    = -f elf64 -Werror $(FEAT_FLAGS) $(INCLUDES) $(D)
# Compile debug version by default
#CFLAGS     = $(CFLAGS_DBG) -Wall -Wchar-subscripts -Wformat-security -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wundef -fno-common -fno-strict-aliasing -fPIC $(FEAT_FLAGS) $(INCLUDES) $(D)
#ASFLAGS    = -f elf64 -Werror -g $(FEAT_FLAGS) $(INCLUDES) $(D)
CC         = gcc
AS         = nasm

ifeq ($(SAFE_DATA),n)
else
CFLAGS += -DSAFE_DATA
ASFLAGS += -DSAFE_DATA
endif

ifeq ($(SAFE_PARAM),n)
else
CFLAGS += -DSAFE_PARAM
ASFLAGS += -DSAFE_PARAM
endif

lib: bin libcrypto.a
static: bin isa-l_crypto_static.a
dll: bin isa-l_crypto.dll

bin:
	mkdir -p $@

isa-l_crypto_static.a: $(objs)
	ar rc $@ $?
	ranlib $@

isa-l_crypto.dll: $(objs)
	$(CC) $(LINKFLAGS) -shared -o $@ $^

bin/%.o: sha1_mb/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: sha1_mb/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: sha256_mb/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: sha256_mb/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: sha512_mb/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: sha512_mb/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: md5_mb/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: md5_mb/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: mh_sha1/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: mh_sha1/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: mh_sha1_murmur3_x64_128/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: mh_sha1_murmur3_x64_128/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: mh_sha256/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: mh_sha256/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: rolling_hash/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: rolling_hash/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: sm3_mb/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: sm3_mb/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

bin/%.o: aes/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/%.o: aes/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

# Examples
ex = \
	sha1_multi_buffer_example \
	gcm_simple_example

ex: lib $(ex)

$(ex): %: %.o
	$(CC) $(LINKFLAGS) -o $@ $< -L. -lcrypto

# Check tests
checks = \
	sha1_mb_test \
	sha1_mb_rand_test \
	sha1_mb_rand_update_test \
	sha1_mb_flush_test \
	sha256_mb_test \
	sha256_mb_rand_test \
	sha256_mb_rand_update_test \
	sha256_mb_flush_test \
	sha512_mb_test \
	sha512_mb_rand_test \
	sha512_mb_rand_update_test \
	md5_mb_test \
	md5_mb_rand_test \
	md5_mb_rand_update_test \
	mh_sha1_test \
	mh_sha256_test \
	rolling_hash2_test \
	sm3_ref_test \
	cbc_std_vectors_test \
	gcm_std_vectors_test \
	gcm_nt_std_vectors_test \
	xts_128_test \
	xts_256_test \
	xts_128_expanded_key_test \
	xts_256_expanded_key_test \
	aes_param_test \
	mh_sha1_param_test

checks: lib $(checks)
$(checks): %: %.o
check: $(checks)
	sh -c './$^'

# Unit tests
tests = \
	sha1_mb_rand_ssl_test \
	sha256_mb_rand_ssl_test \
	sha512_mb_rand_ssl_test \
	md5_mb_rand_ssl_test \
	mh_sha1_update_test \
	mh_sha1_murmur3_x64_128_test \
	mh_sha1_murmur3_x64_128_update_test \
	mh_sha256_update_test \
	sm3_mb_rand_ssl_test \
	sm3_mb_rand_test \
	sm3_mb_rand_update_test \
	sm3_mb_flush_test \
	sm3_mb_test \
	cbc_std_vectors_random_test \
	gcm_std_vectors_random_test \
	gcm_nt_rand_test \
	xts_128_rand \
	xts_128_rand_ossl_test \
	xts_256_rand \
	xts_256_rand_ossl_test

tests: lib $(tests)
$(tests): %: %.o

# Performance tests
perfs = \
	sha1_mb_vs_ossl_perf \
	sha1_mb_vs_ossl_shortage_perf \
	sha256_mb_vs_ossl_perf \
	sha256_mb_vs_ossl_shortage_perf \
	sha512_mb_vs_ossl_perf \
	md5_mb_vs_ossl_perf \
	mh_sha1_perf \
	mh_sha1_murmur3_x64_128_perf \
	mh_sha256_perf \
	rolling_hash2_perf \
	sm3_mb_vs_ossl_perf \
	sm3_mb_vs_ossl_shortage_perf \
	cbc_ossl_perf \
	gcm_ossl_perf \
	xts_128_enc_ossl_perf \
	xts_256_enc_ossl_perf \
	xts_128_enc_perf \
	xts_128_dec_perf \
	xts_128_dec_ossl_perf \
	xts_256_enc_perf \
	xts_256_dec_perf \
	xts_256_dec_ossl_perf

perfs: lib $(perfs)
$(perfs): %: %.o

progs: lib $(progs)

clean:
	$(RM) $(objs) isa-l_crypto_static.a isa-l_crypto.dll $(ex) $(checks) $(tests) $(perfs) $(progs)

libcrypto.a:
sha1_mb_rand_test: sha1_ref.o
sha1_mb_rand_update_test: sha1_ref.o
sha1_mb_flush_test: sha1_ref.o
sha1_mb_rand_ssl_test:  libcrypto.a
sha1_mb_vs_ossl_perf:  libcrypto.a
sha1_mb_vs_ossl_shortage_perf:  libcrypto.a
sha256_mb_rand_ssl_test: sha256_ref.o
sha256_mb_rand_test: sha256_ref.o
sha256_mb_rand_update_test: sha256_ref.o
sha256_mb_flush_test: sha256_ref.o
sha256_mb_rand_ssl_test:  libcrypto.a
sha256_mb_vs_ossl_perf:  libcrypto.a
sha256_mb_vs_ossl_shortage_perf:  libcrypto.a
sha512_mb_rand_test: sha512_ref.o
sha512_mb_rand_update_test: sha512_ref.o
sha512_mb_rand_ssl_test:  libcrypto.a
sha512_mb_vs_ossl_perf:  libcrypto.a
md5_mb_rand_test: md5_ref.o
md5_mb_rand_update_test: md5_ref.o
md5_mb_rand_ssl_test:  libcrypto.a
md5_mb_vs_ossl_perf:  libcrypto.a
mh_sha1_test: mh_sha1_ref.o
mh_sha1_update_test: mh_sha1_ref.o
mh_sha1_murmur3_x64_128_test: mh_sha1_ref.o murmur3_x64_128.o
mh_sha1_murmur3_x64_128_update_test: mh_sha1_ref.o murmur3_x64_128.o
mh_sha1_murmur3_x64_128_perf: mh_sha1_ref.o murmur3_x64_128.o
mh_sha256_test: mh_sha256_ref.o
mh_sha256_update_test: mh_sha256_ref.o
sm3_mb_rand_ssl_test:  libcrypto.a
sm3_mb_rand_ssl_test: sm3_test_helper.o
sm3_mb_rand_update_test:  libcrypto.a
sm3_mb_rand_update_test: sm3_test_helper.o
sm3_mb_flush_test:  libcrypto.a
sm3_mb_flush_test: sm3_test_helper.o
sm3_mb_rand_test:  libcrypto.a
sm3_mb_rand_test: sm3_test_helper.o
sm3_mb_vs_ossl_perf:  libcrypto.a
sm3_mb_vs_ossl_perf: sm3_test_helper.o
sm3_mb_vs_ossl_shortage_perf:  libcrypto.a
sm3_mb_vs_ossl_shortage_perf: sm3_test_helper.o
cbc_ossl_perf:  libcrypto.a
cbc_std_vectors_random_test:  libcrypto.a
gcm_ossl_perf:  libcrypto.a
gcm_std_vectors_random_test:  libcrypto.a
gcm_nt_rand_test:  libcrypto.a
xts_128_enc_ossl_perf:  libcrypto.a
xts_128_dec_ossl_perf:  libcrypto.a
xts_128_rand_ossl_test:  libcrypto.a
xts_256_enc_ossl_perf:  libcrypto.a
xts_256_dec_ossl_perf:  libcrypto.a
xts_256_rand_ossl_test:  libcrypto.a