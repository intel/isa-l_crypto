/**********************************************************************
  Copyright(c) 2022 Linaro Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Linaro Corporation nor the names of its
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#ifndef XXH_INLINE_ALL
#  define XXH_INLINE_ALL
#endif
#include <xxhash.h>

#include "endian_helper.h"
#include "test.h"
#include "xxhash_mb.h"

#define MAX_BUF_SIZE	(16 << 20)	// 16MB
#define MIN_BUF_SIZE	1

#define SEGMENT_MASK		0xFFFFFFFF00000000UL

#define TEST_PERF_LOOPS		1000
#define TEST_PERF_LEN		256

struct buf_list {
	void *addr;
	size_t size;
	struct buf_list *next;
};

typedef enum {
	XXH32_TEST = 0,
	XXH64_TEST,
} XXH_TEST_TYPE;

/*
 * Create a buffer list. Each list item contains with random buffer size.
 * The next field of last item is always NULL.
 */
static struct buf_list *alloc_buffer(int nums, size_t size)
{
	struct buf_list *list;
	struct timeval tv;
	int i;

	if (nums < 0)
		return NULL;
	list = malloc(sizeof(struct buf_list) * nums);
	if (!list)
		return NULL;
	gettimeofday(&tv, NULL);
	srand((unsigned int)tv.tv_usec);
	for (i = 0; i < nums; i++) {
		list[i].next = NULL;
		if (size)
			list[i].size = size;
		else
			list[i].size = (size_t)(rand() / 100000);
		if (list[i].size > MAX_BUF_SIZE)
			list[i].size = MAX_BUF_SIZE;
		else if (list[i].size < MIN_BUF_SIZE)
			list[i].size = MIN_BUF_SIZE;
		list[i].addr = malloc(list[i].size);
		if (!list[i].addr)
			goto out;
		if (i > 0)
			list[i - 1].next = &list[i];
	}
	return list;
      out:
	for (; i > 1; i--)
		free(list[i - 1].addr);
	free(list);
	return NULL;
}

/* Free the whole buffer list. */
static void free_buffer(struct buf_list *list)
{
	struct buf_list *p = list;

	while (p) {
		if (p->addr)
			free(p->addr);
		p = p->next;
	}
	free(list);
}

void init_buf(uint8_t *buf, uint8_t val, size_t len)
{
	for (int i = 0; i < len; i++) {
		buf[i] = val + ((i / 8) * 0x10) + (i % 8);
	}
}

void dump_buf(unsigned char *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i += 16) {
		printf("[0x%x]: %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x "
		       "%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
		       i, buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
		       buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
		       buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
		       buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]);
	}
}

/* Fill random data into the whole buffer list. */
static void fill_rand_buffer(struct buf_list *list)
{
	struct buf_list *p = list;
	unsigned char *u;
	int i;

	while (p) {
		if (p->addr) {
			u = (unsigned char *)p->addr;
			for (i = 0; i < p->size; i++)
				u[i] = (unsigned char)rand();
		}
		p = p->next;
	}
}

int verify_digest32(struct buf_list *list, uint32_t digest)
{
	XXH32_state_t state;
	XXH32_hash_t h32;
	struct buf_list *p = list;
	int updated = 0;

	XXH32_reset(&state, 0);
	while (p) {
		if (p->addr) {
			updated |= 1;
			XXH32_update(&state, p->addr, p->size);
		}
		p = p->next;
	}
	if (!updated) {
		fprintf(stderr, "Fail to get digest value for verification!\n");
		return -EINVAL;
	}
	h32 = XXH32_digest(&state);
	if (h32 == digest)
		return 0;
	printf("Input digest vs verified digest: %x VS %x\n", digest, h32);
	return -EINVAL;
}

int verify_digest64(struct buf_list *list, uint64_t digest)
{
	XXH64_state_t state;
	XXH64_hash_t h64;
	struct buf_list *p = list;
	int updated = 0;

	XXH64_reset(&state, 0);
	while (p) {
		if (p->addr) {
			updated |= 1;
			XXH64_update(&state, p->addr, p->size);
		}
		p = p->next;
	}
	if (!updated) {
		fprintf(stderr, "Fail to get digest value for verification!\n");
		return -EINVAL;
	}
	h64 = XXH64_digest(&state);
	if (h64 == digest)
		return 0;
	printf("Input digest vs verified digest: %lx VS %lx\n", digest, h64);
	return -EINVAL;
}

struct ctx_user_data {
	uint32_t seed;
};

int run_sb_perf32(int len)
{
	struct buf_list *list = NULL, *p = NULL;
	int ret, t;
	int buf_cnt = 1;
	struct perf start, stop;
	XXH32_state_t state;
	int updated = 0;

	list = alloc_buffer(buf_cnt, len);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		ret = -ENOMEM;
		goto out;
	}
	fill_rand_buffer(list);

	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		p = list;
		updated = 0;
		XXH32_reset(&state, 0);
		while (p) {
			if (p->addr) {
				updated |= 1;
				XXH32_update(&state, p->addr, p->size);
			}
			p = p->next;
		}
		if (!updated) {
			fprintf(stderr, "Fail to get digest value!\n");
			goto out;
		}
		XXH32_digest(&state);
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * t);

	free_buffer(list);
	return 0;
      out:
	if (list)
		free_buffer(list);
	return ret;
}

int run_sb_perf64(int len)
{
	struct buf_list *list = NULL, *p = NULL;
	int ret, t;
	int buf_cnt = 1;
	struct perf start, stop;
	XXH64_state_t state;
	int updated = 0;

	list = alloc_buffer(buf_cnt, len);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		ret = -ENOMEM;
		goto out;
	}
	fill_rand_buffer(list);

	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		p = list;
		updated = 0;
		XXH64_reset(&state, 0);
		while (p) {
			if (p->addr) {
				updated |= 1;
				XXH64_update(&state, p->addr, p->size);
			}
			p = p->next;
		}
		if (!updated) {
			fprintf(stderr, "Fail to get digest value!\n");
			goto out;
		}
		XXH64_digest(&state);
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * t);

	free_buffer(list);
	return 0;
      out:
	if (list)
		free_buffer(list);
	return ret;
}

int main(void)
{
	char str[64];
	int i, len, cnt;

#ifdef QUICK_TEST
	cnt = 8;
#else
	cnt = 15;
#endif

	printf("Test for XXH32:\n");
	for (i = 0, len = TEST_PERF_LEN; i < cnt; i++) {
		if (len >= 1024 * 1024)
			sprintf(str, "%dMB", len >> 20);
		else if (len >= 1024)
			sprintf(str, "%dKB", len >> 10);
		else
			sprintf(str, "%dB", len);
		printf("Test data buffer with %s size:\n", str);
		run_sb_perf32(len);
		len <<= 1;
	}
	printf("Test for XXH64:\n");
	for (i = 0, len = TEST_PERF_LEN; i < cnt; i++) {
		if (len >= 1024 * 1024)
			sprintf(str, "%dMB", len >> 20);
		else if (len >= 1024)
			sprintf(str, "%dKB", len >> 10);
		else
			sprintf(str, "%dB", len);
		printf("Test data buffer with %s size:\n", str);
		run_sb_perf64(len);
		len <<= 1;
	}
	return 0;
}
