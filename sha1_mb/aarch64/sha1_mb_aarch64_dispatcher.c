/**********************************************************************
  Copyright(c) 2019 Arm Corporation All rights reserved.

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

DEFINE_INTERFACE_DISPATCHER(sha1_ctx_mgr_submit)
{

	unsigned long auxval = getauxval(AT_HWCAP);
	if (auxval & HWCAP_SHA1)
		return PROVIDER_INFO(sha1_ctx_mgr_submit_ce);

	if (auxval & HWCAP_ASIMD) {
		switch (get_micro_arch_id()) {
		case MICRO_ARCH_ID(ARM, NEOVERSE_N1):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A57):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A72):	// fall through
			return PROVIDER_INFO(sha1_ctx_mgr_submit_asimd);
		default:
			break;
		}
	}

	return PROVIDER_BASIC(sha1_ctx_mgr_submit);

}

DEFINE_INTERFACE_DISPATCHER(sha1_ctx_mgr_init)
{
	unsigned long auxval = getauxval(AT_HWCAP);
	if (auxval & HWCAP_SHA1)
		return PROVIDER_INFO(sha1_ctx_mgr_init_ce);

	if (auxval & HWCAP_ASIMD) {
		switch (get_micro_arch_id()) {
		case MICRO_ARCH_ID(ARM, NEOVERSE_N1):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A57):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A72):	// fall through
			return PROVIDER_INFO(sha1_ctx_mgr_init_asimd);
		default:
			break;
		}
	}

	return PROVIDER_BASIC(sha1_ctx_mgr_init);

}

DEFINE_INTERFACE_DISPATCHER(sha1_ctx_mgr_flush)
{
	unsigned long auxval = getauxval(AT_HWCAP);
	if (auxval & HWCAP_SHA1)
		return PROVIDER_INFO(sha1_ctx_mgr_flush_ce);

	if (auxval & HWCAP_ASIMD) {
		switch (get_micro_arch_id()) {
		case MICRO_ARCH_ID(ARM, NEOVERSE_N1):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A57):	// fall through
		case MICRO_ARCH_ID(ARM, CORTEX_A72):	// fall through
			return PROVIDER_INFO(sha1_ctx_mgr_flush_asimd);
		default:
			break;
		}
	}

	return PROVIDER_BASIC(sha1_ctx_mgr_flush);

}
