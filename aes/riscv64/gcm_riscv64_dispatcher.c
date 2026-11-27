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

#include <riscv64_multibinary.h>

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_128)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_128_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_128_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_128)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_128_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_128_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_precomp_128)
{
        return PROVIDER_INFO(aes_gcm_precomp_128_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_256)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_256_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_256_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_256)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_256_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_256_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_precomp_256)
{
        return PROVIDER_INFO(aes_gcm_precomp_256_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_128_update)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_128_update_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_128_update_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_128_finalize)
{
        return PROVIDER_INFO(aes_gcm_enc_128_finalize_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_128_update)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_128_update_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_128_update_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_128_finalize)
{
        return PROVIDER_INFO(aes_gcm_dec_128_finalize_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_256_update)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_256_update_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_256_update_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_256_finalize)
{
        return PROVIDER_INFO(aes_gcm_enc_256_finalize_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_256_update)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_256_update_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_256_update_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_256_finalize)
{
        return PROVIDER_INFO(aes_gcm_dec_256_finalize_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_init_256) { return PROVIDER_INFO(aes_gcm_init_256_base); }

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_init_128) { return PROVIDER_INFO(aes_gcm_init_128_base); }

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_128_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_128_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_128_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_128_update_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_128_update_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_128_update_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_128_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_128_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_128_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_128_update_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_128_update_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_128_update_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_256_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_256_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_256_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_enc_256_update_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_enc_256_update_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_enc_256_update_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_256_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_256_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_256_nt_base);
}

DEFINE_INTERFACE_DISPATCHER(_aes_gcm_dec_256_update_nt)
{
#if HAVE_RISCV_ZVK
        if (is_zvk_aes_available())
                return PROVIDER_INFO(aes_gcm_dec_256_update_nt_zvk);
#endif
        return PROVIDER_INFO(aes_gcm_dec_256_update_nt_base);
}
