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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "xxhash_mb.h"

#define LANE_INDEX_MASK   0xff
#define LANE_LENGTH_SHIFT 8

#define LANE_IS_NOT_FINISHED(state, i)                                                             \
        (((state->lens[i] & ~LANE_INDEX_MASK) != 0) && state->ldata[i].job_in_lane != NULL)
#define LANE_IS_FINISHED(state, i)                                                                 \
        (((state->lens[i] & ~LANE_INDEX_MASK) == 0) && state->ldata[i].job_in_lane != NULL)
#define LANE_IS_FREE(state, i)                                                                     \
        (((state->lens[i] & ~LANE_INDEX_MASK) == 0) && state->ldata[i].job_in_lane == NULL)
#define LANE_IS_INVALID(state, i)                                                                  \
        (((state->lens[i] & ~LANE_INDEX_MASK) != 0) && state->ldata[i].job_in_lane == NULL)

#define LANE_LENGTH(idx, len) ((len << LANE_LENGTH_SHIFT) | (idx & LANE_INDEX_MASK))

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define XXH32_4GB_SHIFT 32

extern int
xxh32_mb_sve_max_lanes(void);
extern void
xxh32_mb_sve(XXH32_JOB **job_vec, int job_cnt, int block_cnt, int overflow);
extern void
xxh64_mb_sve(XXH64_JOB **job_vec, int job_cnt, int block_cnt);

void
xxh32_mb_mgr_init_sve(XXH32_MB_JOB_MGR *state)
{
        unsigned int i;

        state->max_lanes_inuse = xxh32_mb_sve_max_lanes();
        switch (state->max_lanes_inuse) {
        case 4:
                // SVE128
                state->unused_lanes[0] = 0x7f7f7f7f03020100;
                state->unused_lanes[1] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[4] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[5] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[6] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[7] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 8:
                // SVE256
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[4] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[5] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[6] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[7] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 16:
                // SVE512
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x0f0e0d0c0b0a0908;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[4] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[5] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[6] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[7] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 32:
                // SVE1024
                /* Each byte indicates a lane index that is from 0 to 31. */
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x0f0e0d0c0b0a0908;
                state->unused_lanes[2] = 0x1716151413121110;
                state->unused_lanes[3] = 0x1f1e1d1c1b1a1918;
                state->unused_lanes[4] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[5] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[6] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[7] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 64:
                // SVE2048
                /* Each byte indicates a lane index that is from 0 to 63. */
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x0f0e0d0c0b0a0908;
                state->unused_lanes[2] = 0x1716151413121110;
                state->unused_lanes[3] = 0x1f1e1d1c1b1a1918;
                state->unused_lanes[4] = 0x2726252423222120;
                state->unused_lanes[5] = 0x2f2e2d2c2b2a2928;
                state->unused_lanes[6] = 0x3736353433323130;
                state->unused_lanes[7] = 0x3f3e3d3c3b3a3938;
                break;
        default:
                state->max_lanes_inuse = 0;
                return;
        }

        state->num_lanes_inuse = 0;
        for (i = 0; i < state->max_lanes_inuse; i++) {
                state->lens[i] = i;
                state->ldata[i].job_in_lane = NULL;
        }
        for (; i < state->max_lanes_inuse; i++) {
                state->lens[i] = 0x7f;
                state->ldata[i].job_in_lane = NULL;
        }
        state->region_start = 0;
        state->region_end = 0;
}

static int
xxh32_mb_mgr_do_jobs(XXH32_MB_JOB_MGR *state)
{
        int job_cnt, i, blocks, min_len = 0;
        XXH32_JOB *job_vecs[XXH32_MAX_LANES];
        uint64_t start, end;
        int overflow;

        if (state->num_lanes_inuse == 0)
                return -EINVAL;
        start = state->region_start >> XXH32_4GB_SHIFT;
        end = state->region_end >> XXH32_4GB_SHIFT;
        /* find the minimal length of all lanes */
        // job_idx is the index of job_vecs[]
        // i is the index of all lanes
        // min_idx is the index of minimal lane length
        for (i = 0, job_cnt = 0; i < state->max_lanes_inuse && job_cnt < state->num_lanes_inuse;
             i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        /*
                         * state->lens[] is the combination of lane index
                         * and length.
                         * In MD5, the length must be large than 16 bytes.
                         * Why?
                         * Each operation in MD5 is based on 32-byte. So it's
                         * reasonable that the minimal length is large than
                         * 16 bytes.
                         * In XXH32, the minimal length is also large than
                         * 16 bytes.
                         */
                        if (job_cnt)
                                min_len = min(min_len, state->lens[i]);
                        else
                                min_len = state->lens[i];
                        job_vecs[job_cnt++] = state->ldata[i].job_in_lane;
                }
        }
        if (min_len <= 0)
                return -EINVAL;
        min_len &= ~LANE_INDEX_MASK;
        // Only block data could be accelerated by SVE instructions.
        // Remained data should be handled in other routine.
        blocks = min_len >> LANE_LENGTH_SHIFT;

        // If start equals to end, it means that all job buffers are in the
        // same 4GB slot. So memory copy could be skipped in xxh32_mb_sve().
        // If start doesn't equal to end, it means that more than one 4GB
        // slot are used by all job buffers. So memory copy is used to format
        // a traverse matrix in xxh32_mb_sve().
        overflow = (start == end) ? 0 : 1;
        xxh32_mb_sve(job_vecs, job_cnt, blocks, overflow);

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        state->lens[i] -= min_len;
                        state->ldata[i].job_in_lane->blk_len -= blocks;
                        state->ldata[i].job_in_lane->buffer += blocks << XXH32_LOG2_BLOCK_SIZE;
                }
        }
        return 0;
}

static void
xxh32_mb_mgr_insert_job(XXH32_MB_JOB_MGR *state, XXH32_JOB *job)
{
        int grp = -1;
        int lane_idx; // unused lane index
        int i;

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_FREE(state, i)) {
                        grp = i / LANE_LENGTH_SHIFT;
                        break;
                }
        }

        // fatal error
        assert(grp >= 0);

        // add job into lanes
        lane_idx = state->unused_lanes[grp] & LANE_INDEX_MASK;

        // fatal error
        assert(lane_idx < state->max_lanes_inuse);

        state->lens[lane_idx] = LANE_LENGTH(lane_idx, job->blk_len);
        state->ldata[lane_idx].job_in_lane = job;
        state->unused_lanes[grp] >>= LANE_LENGTH_SHIFT;
        state->num_lanes_inuse++;
}

static XXH32_JOB *
xxh32_mb_mgr_free_lane(XXH32_MB_JOB_MGR *state)
{
        int i;
        XXH32_JOB *ret = NULL;

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_FINISHED(state, i)) {
                        int grp = i / 8;
                        state->unused_lanes[grp] <<= 8;
                        state->unused_lanes[grp] |= i;
                        state->num_lanes_inuse--;
                        ret = state->ldata[i].job_in_lane;
                        ret->status = STS_COMPLETED;
                        state->ldata[i].job_in_lane = NULL;
                        break;
                }
        }
        return ret;
}

XXH32_JOB *
xxh32_mb_mgr_submit_sve(XXH32_MB_JOB_MGR *state, XXH32_JOB *job)
{
        XXH32_JOB *ret;

        // add job into lanes
        xxh32_mb_mgr_insert_job(state, job);

        ret = xxh32_mb_mgr_free_lane(state);
        if (ret)
                goto out;
        // submit will wait data ready in all lanes
        if (state->num_lanes_inuse < state->max_lanes_inuse) {
                ret = NULL;
                goto out;
        }
        xxh32_mb_mgr_do_jobs(state);
        ret = xxh32_mb_mgr_free_lane(state);
out:
        return ret;
}

XXH32_JOB *
xxh32_mb_mgr_flush_sve(XXH32_MB_JOB_MGR *state)
{
        XXH32_JOB *ret;

        ret = xxh32_mb_mgr_free_lane(state);
        if (ret) {
                return ret;
        }

        xxh32_mb_mgr_do_jobs(state);
        return xxh32_mb_mgr_free_lane(state);
}

void
xxh64_mb_mgr_init_sve(XXH64_MB_JOB_MGR *state)
{
        unsigned int i;

        state->max_lanes_inuse = xxh32_mb_sve_max_lanes() / 2;
        switch (state->max_lanes_inuse) {
        case 2:
                // SVE128
                state->unused_lanes[0] = 0x7f7f7f7f7f7f0100;
                state->unused_lanes[1] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 4:
                // SVE256
                state->unused_lanes[0] = 0x7f7f7f7f03020100;
                state->unused_lanes[1] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 8:
                // SVE512
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 16:
                // SVE1024
                // Each byte indicates a lane index that is from 0 to 15.
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x0f0e0d0c0b0a0908;
                state->unused_lanes[2] = 0x7f7f7f7f7f7f7f7f;
                state->unused_lanes[3] = 0x7f7f7f7f7f7f7f7f;
                break;
        case 32:
                // SVE2048
                // Each byte indicates a lane index that is from 0 to 31.
                state->unused_lanes[0] = 0x0706050403020100;
                state->unused_lanes[1] = 0x0f0e0d0c0b0a0908;
                state->unused_lanes[2] = 0x1716151413121110;
                state->unused_lanes[3] = 0x1f1e1d1c1b1a1918;
                break;
        default:
                state->max_lanes_inuse = 0;
                return;
        }

        state->num_lanes_inuse = 0;
        for (i = 0; i < state->max_lanes_inuse; i++) {
                state->lens[i] = i;
                state->ldata[i].job_in_lane = NULL;
        }
        for (; i < state->max_lanes_inuse; i++) {
                state->lens[i] = 0x7f;
                state->ldata[i].job_in_lane = NULL;
        }
}

static int
xxh64_mb_mgr_do_jobs(XXH64_MB_JOB_MGR *state)
{
        int job_cnt, i, blocks, min_len = 0;
        XXH64_JOB *job_vecs[XXH64_MAX_LANES];

        if (state->num_lanes_inuse == 0)
                return -EINVAL;
        // find the minimal length of all lanes
        // job_idx is the index of job_vecs[]
        // i is the index of all lanes
        for (i = 0, job_cnt = 0; i < state->max_lanes_inuse && job_cnt < state->num_lanes_inuse;
             i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        /*
                         * state->lens[] is the combination of lane index
                         * and length.
                         */
                        if (job_cnt)
                                min_len = min(min_len, state->lens[i]);
                        else
                                min_len = state->lens[i];
                        job_vecs[job_cnt++] = state->ldata[i].job_in_lane;
                }
        }
        if (min_len <= 0)
                return -EINVAL;
        min_len &= ~LANE_INDEX_MASK;
        // Only block data could be accelerated by SVE instructions.
        // Remained data should be handled in other routine.
        blocks = min_len >> LANE_LENGTH_SHIFT;
        xxh64_mb_sve(job_vecs, job_cnt, blocks);

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        state->lens[i] -= min_len;
                        state->ldata[i].job_in_lane->blk_len -= blocks;
                        state->ldata[i].job_in_lane->buffer += blocks << XXH64_LOG2_BLOCK_SIZE;
                }
        }
        return 0;
}

static void
xxh64_mb_mgr_insert_job(XXH64_MB_JOB_MGR *state, XXH64_JOB *job)
{
        int grp = -1;
        int lane_idx;
        int i;

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_FREE(state, i)) {
                        grp = i / LANE_LENGTH_SHIFT;
                        break;
                }
        }

        // fatal error
        assert(grp >= 0);

        // add job into lanes
        lane_idx = state->unused_lanes[grp] & LANE_INDEX_MASK;
        // fatal error
        assert(lane_idx < state->max_lanes_inuse);

        state->lens[lane_idx] = LANE_LENGTH(lane_idx, job->blk_len);
        state->ldata[lane_idx].job_in_lane = job;
        state->unused_lanes[grp] >>= LANE_LENGTH_SHIFT;
        state->num_lanes_inuse++;
}

static XXH64_JOB *
xxh64_mb_mgr_free_lane(XXH64_MB_JOB_MGR *state)
{
        int i;
        XXH64_JOB *ret = NULL;

        for (i = 0; i < state->max_lanes_inuse; i++) {
                if (LANE_IS_FINISHED(state, i)) {
                        int grp = i / 8;

                        state->unused_lanes[grp] <<= 8;
                        state->unused_lanes[grp] |= i;
                        state->num_lanes_inuse--;
                        ret = state->ldata[i].job_in_lane;
                        ret->status = STS_COMPLETED;
                        state->ldata[i].job_in_lane = NULL;
                        break;
                }
        }
        return ret;
}

XXH64_JOB *
xxh64_mb_mgr_submit_sve(XXH64_MB_JOB_MGR *state, XXH64_JOB *job)
{
        XXH64_JOB *ret;

        // add job into lanes
        xxh64_mb_mgr_insert_job(state, job);

        ret = xxh64_mb_mgr_free_lane(state);
        if (ret)
                goto out;
        // submit will wait data ready in all lanes
        if (state->num_lanes_inuse < state->max_lanes_inuse) {
                ret = NULL;
                goto out;
        }
        xxh64_mb_mgr_do_jobs(state);
        ret = xxh64_mb_mgr_free_lane(state);
out:
        return ret;
}

XXH64_JOB *
xxh64_mb_mgr_flush_sve(XXH64_MB_JOB_MGR *state)
{
        XXH64_JOB *ret;

        ret = xxh64_mb_mgr_free_lane(state);
        if (ret)
                return ret;

        xxh64_mb_mgr_do_jobs(state);
        return xxh64_mb_mgr_free_lane(state);
}
