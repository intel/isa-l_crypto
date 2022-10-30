/**********************************************************************
  Copyright(c) 2019-2022 Arm Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Arm Corporation nor the names of its
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
#include <aarch64_multibinary.h>

extern int sm3_mb_sve_max_lanes(void);

/* run time check of SVE2 regardless whether compile environment
 * has HWCAP2_SVE2 set
 */
#ifndef HWCAP2_SVE2
#define HWCAP2_SVE2	(1 << 1)
#endif

#define CAP_SVE	1
#define CAP_SVE2	2
#define CAP_NOSVE	0

static inline int sve_capable(unsigned long auxval)
{
	if (auxval & HWCAP_SVE) {
		if (getauxval(AT_HWCAP2) & HWCAP2_SVE2) {
			return CAP_SVE2;
		}
		if (sm3_mb_sve_max_lanes() >= 8)
			return CAP_SVE;
	}
	return CAP_NOSVE;
}

DEFINE_INTERFACE_DISPATCHER(sm3_ctx_mgr_submit)
{
	unsigned long auxval = getauxval(AT_HWCAP);

	if (auxval & HWCAP_SM3)
		return PROVIDER_INFO(sm3_ctx_mgr_submit_sm);

	switch (sve_capable(auxval)) {
	case CAP_SVE:
		return PROVIDER_INFO(sm3_ctx_mgr_submit_sve);
	case CAP_SVE2:
		return PROVIDER_INFO(sm3_ctx_mgr_submit_sve2);
	default:
		break;
	}

	if (auxval & HWCAP_ASIMD)
		return PROVIDER_INFO(sm3_ctx_mgr_submit_asimd);
	return PROVIDER_BASIC(sm3_ctx_mgr_submit);
}

DEFINE_INTERFACE_DISPATCHER(sm3_ctx_mgr_init)
{
	unsigned long auxval = getauxval(AT_HWCAP);

	if (auxval & HWCAP_SM3)
		return PROVIDER_INFO(sm3_ctx_mgr_init_sm);

	switch (sve_capable(auxval)) {
	case CAP_SVE:
		return PROVIDER_INFO(sm3_ctx_mgr_init_sve);
	case CAP_SVE2:
		return PROVIDER_INFO(sm3_ctx_mgr_init_sve2);
	default:
		break;
	}

	if (auxval & HWCAP_ASIMD)
		return PROVIDER_INFO(sm3_ctx_mgr_init_asimd);
	return PROVIDER_BASIC(sm3_ctx_mgr_init);
}

DEFINE_INTERFACE_DISPATCHER(sm3_ctx_mgr_flush)
{
	unsigned long auxval = getauxval(AT_HWCAP);

	if (auxval & HWCAP_SM3)
		return PROVIDER_INFO(sm3_ctx_mgr_flush_sm);

	switch (sve_capable(auxval)) {
	case CAP_SVE:
		return PROVIDER_INFO(sm3_ctx_mgr_flush_sve);
	case CAP_SVE2:
		return PROVIDER_INFO(sm3_ctx_mgr_flush_sve2);
	default:
		break;
	}

	if (auxval & HWCAP_ASIMD)
		return PROVIDER_INFO(sm3_ctx_mgr_flush_asimd);
	return PROVIDER_BASIC(sm3_ctx_mgr_flush);
}
