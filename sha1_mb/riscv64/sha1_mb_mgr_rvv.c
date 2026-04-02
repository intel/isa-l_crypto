/**********************************************************************
  Copyright (c) 2026 Institute of Software Chinese Academy of Sciences (ISCAS).

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

#include <stddef.h>
#include <sha1_mb.h>
#include <assert.h>
#include "endian_helper.h"

extern void
sha1_riscv64_x1(const uint8_t *data, int num_blocks, uint32_t digest[]);

static inline void
sha1_job_x1(ISAL_SHA1_JOB *job, int blocks)
{
        sha1_riscv64_x1(job->buffer, blocks, job->result_digest);
}

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define SHA1_MB_RVV_MAX_LANES 4
void
sha1_mb_rvv_x4(ISAL_SHA1_MB_ARGS_X16 *, int);

#define LANE_IS_NOT_FINISHED(state, i)                                                             \
        (((state->lens[i] & (~0xf)) != 0) && state->ldata[i].job_in_lane != NULL)
#define LANE_IS_FINISHED(state, i)                                                                 \
        (((state->lens[i] & (~0xf)) == 0) && state->ldata[i].job_in_lane != NULL)
#define LANE_IS_FREE(state, i)                                                                     \
        (((state->lens[i] & (~0xf)) == 0) && state->ldata[i].job_in_lane == NULL)
#define LANE_IS_INVALID(state, i)                                                                  \
        (((state->lens[i] & (~0xf)) != 0) && state->ldata[i].job_in_lane == NULL)

void
sha1_mb_mgr_init_rvv(ISAL_SHA1_MB_JOB_MGR *state)
{
        unsigned int i;

        state->unused_lanes = 0xf;
        state->num_lanes_inuse = 0;
        for (i = 0; i < SHA1_MB_RVV_MAX_LANES; i++) {
                state->unused_lanes <<= 4;
                state->unused_lanes |= SHA1_MB_RVV_MAX_LANES - 1 - i;
                state->lens[i] = i;
                state->ldata[i].job_in_lane = 0;
        }

        // lanes > SHA1_MB_RVV_MAX_LANES is invalid lane
        for (; i < ISAL_SHA1_MAX_LANES; i++) {
                state->lens[i] = 0xf;
                state->ldata[i].job_in_lane = 0;
        }
}

static void
sha1_mb_mgr_run_rvv(ISAL_SHA1_MB_JOB_MGR *state, int lane_idx_array[], int lanes, int blocks)
{
        int j, k;

        /* Marshal: copy digest and data_ptr from individual jobs into state->args */
        for (j = 0; j < lanes; j++) {
                ISAL_SHA1_JOB *job = state->ldata[lane_idx_array[j]].job_in_lane;
                for (k = 0; k < ISAL_SHA1_DIGEST_NWORDS; k++)
                        state->args.digest[k][j] = job->result_digest[k];
                state->args.data_ptr[j] = job->buffer;
        }
        /* Fill remaining lanes (up to 4) with dummy data from lane 0 */
        for (; j < SHA1_MB_RVV_MAX_LANES; j++) {
                for (k = 0; k < ISAL_SHA1_DIGEST_NWORDS; k++)
                        state->args.digest[k][j] = state->args.digest[k][0];
                state->args.data_ptr[j] = state->args.data_ptr[0];
        }

        sha1_mb_rvv_x4(&state->args, blocks);

        /* Unmarshal: copy digest back from state->args to individual jobs */
        for (j = 0; j < lanes; j++) {
                ISAL_SHA1_JOB *job = state->ldata[lane_idx_array[j]].job_in_lane;
                for (k = 0; k < ISAL_SHA1_DIGEST_NWORDS; k++)
                        job->result_digest[k] = state->args.digest[k][j];
        }
}

static int
sha1_mb_mgr_do_jobs(ISAL_SHA1_MB_JOB_MGR *state)
{
        int lane_idx, len, i, lanes, blocks;
        int lane_idx_array[ISAL_SHA1_MAX_LANES];

        if (state->num_lanes_inuse == 0) {
                return -1;
        }
        lanes = 0, len = 0;
        for (i = 0; i < ISAL_SHA1_MAX_LANES && lanes < state->num_lanes_inuse; i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        if (lanes)
                                len = min(len, state->lens[i]);
                        else
                                len = state->lens[i];
                        lane_idx_array[lanes] = i;
                        lanes++;
                }
        }

        if (lanes == 0)
                return -1;
        lane_idx = len & 0xf;
        len = len & (~0xf);
        blocks = len >> 4;

        if (lanes >= 3) {
                sha1_mb_mgr_run_rvv(state, lane_idx_array, lanes, blocks);
        } else {
                sha1_job_x1(state->ldata[lane_idx_array[0]].job_in_lane, blocks);
                if (lanes >= 2) {
                        sha1_job_x1(state->ldata[lane_idx_array[1]].job_in_lane, blocks);
                }
        }

        // only return the min length job
        for (i = 0; i < ISAL_SHA1_MAX_LANES; i++) {
                if (LANE_IS_NOT_FINISHED(state, i)) {
                        state->lens[i] -= len;
                        state->ldata[i].job_in_lane->len -= len;
                        state->ldata[i].job_in_lane->buffer += len << 2;
                }
        }
        return lane_idx;
}

static ISAL_SHA1_JOB *
sha1_mb_mgr_free_lane(ISAL_SHA1_MB_JOB_MGR *state)
{
        int i;
        ISAL_SHA1_JOB *ret = NULL;

        for (i = 0; i < SHA1_MB_RVV_MAX_LANES; i++) {
                if (LANE_IS_FINISHED(state, i)) {
                        state->unused_lanes <<= 4;
                        state->unused_lanes |= i;
                        state->num_lanes_inuse--;
                        ret = state->ldata[i].job_in_lane;
                        ret->status = ISAL_STS_COMPLETED;
                        state->ldata[i].job_in_lane = NULL;
                        break;
                }
        }
        return ret;
}

static void
sha1_mb_mgr_insert_job(ISAL_SHA1_MB_JOB_MGR *state, ISAL_SHA1_JOB *job)
{
        int lane_idx;
        // add job into lanes
        lane_idx = state->unused_lanes & 0xf;
        // fatal error
        assert(lane_idx < SHA1_MB_RVV_MAX_LANES);
        state->lens[lane_idx] = (job->len << 4) | lane_idx;
        state->ldata[lane_idx].job_in_lane = job;
        state->unused_lanes >>= 4;
        state->num_lanes_inuse++;
}

ISAL_SHA1_JOB *
sha1_mb_mgr_submit_rvv(ISAL_SHA1_MB_JOB_MGR *state, ISAL_SHA1_JOB *job)
{
#ifndef NDEBUG
        int lane_idx;
#endif
        ISAL_SHA1_JOB *ret;

        // add job into lanes
        sha1_mb_mgr_insert_job(state, job);

        ret = sha1_mb_mgr_free_lane(state);
        if (ret != NULL) {
                return ret;
        }
        // submit will wait all lane has data
        if (state->num_lanes_inuse < SHA1_MB_RVV_MAX_LANES)
                return NULL;
#ifndef NDEBUG
        lane_idx = sha1_mb_mgr_do_jobs(state);
        assert(lane_idx != -1);
#else
        sha1_mb_mgr_do_jobs(state);
#endif

        // ~ i = lane_idx;
        ret = sha1_mb_mgr_free_lane(state);
        return ret;
}

ISAL_SHA1_JOB *
sha1_mb_mgr_flush_rvv(ISAL_SHA1_MB_JOB_MGR *state)
{
        ISAL_SHA1_JOB *ret;
        ret = sha1_mb_mgr_free_lane(state);
        if (ret) {
                return ret;
        }

        sha1_mb_mgr_do_jobs(state);
        return sha1_mb_mgr_free_lane(state);
}
