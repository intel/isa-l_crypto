/**********************************************************************
  Copyright(c) 2020 Arm Corporation All rights reserved.

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

#ifndef KEY_LEN
#define KEY_LEN 128
    .arch armv8-a+crypto
    .text
#endif
#define NUM_ROUNDS(a) (7+(a)/32)

#define AAD_LEN_OFF                 16
#define IN_LENGTH_OFF               24
#define PARTIAL_BLOCK_ENC_KEY_OFF   32
#define PARTIAL_BLOCK_LENGTH_OFF    80
#define CTR_OFF                     64
#define ORIG_IV_OFF                 48

#define FN_NAME(fn,mode,post) aes_gcm_##fn##_##mode####post##_aes
#define START_FUNC(fn,mode,post) .global FN_NAME(fn,mode,post); \
    .type   FN_NAME(fn,mode,post), %function; \
    FN_NAME(fn,mode,post):
#define END_FUNC(fn,mode,post)   .size  FN_NAME(fn,mode,post), .-FN_NAME(fn,mode,post)

/*
Macros
*/

.macro  declare_var_vector_reg name:req,reg:req
    q\name      .req    q\reg
    v\name      .req    v\reg
    s\name      .req    s\reg
    d\name      .req    d\reg
.endm
#if KEY_LEN==128
#define KEY_REGS 0,1,2,3,4,5,6,7,8
declare_var_vector_reg  Key0,21
declare_var_vector_reg  Key1,22
declare_var_vector_reg  Key2,23
declare_var_vector_reg  Key3,24
declare_var_vector_reg  Key4,25
declare_var_vector_reg  Key5,26
declare_var_vector_reg  Key6,27
declare_var_vector_reg  Key7,28
declare_var_vector_reg  Key8,29
declare_var_vector_reg  KeyLast0,30
declare_var_vector_reg  KeyLast1,31
declare_var_vector_reg  HashKey,20
declare_var_vector_reg  tmp0,16
declare_var_vector_reg  tmp1,17
declare_var_vector_reg  zero,18
declare_var_vector_reg  poly,19
declare_var_vector_reg  HashKeyIter,7   //only be used in prcomp
declare_var_vector_reg  AadHash,    7
declare_var_vector_reg  tmp2,6
declare_var_vector_reg  reg0,6
declare_var_vector_reg  reg1,5
declare_var_vector_reg  Ctr,4
declare_var_vector_reg  dat,3
declare_var_vector_reg  Partial,3
declare_var_vector_reg  Plain,3
declare_var_vector_reg  AadLen,3
declare_var_vector_reg  OrigIV,3
declare_var_vector_reg  Crypt,2
declare_var_vector_reg  one,1
declare_var_vector_reg  Len,0
.macro load_keys    key_addr:req
    ldr     qKey0,[\key_addr],16
    ldp     qKey1,qKey2,[\key_addr],32
    ld1     {vKey3.4s-vKey6.4s},[\key_addr],64
    ld1     {vKey7.4s-vKeyLast1.4s},[\key_addr],64
.endm
.macro  push_stack
.endm
.macro  pop_stack
.endm
#elif KEY_LEN==192
#define KEY_REGS 0,1,2,3,4,5,6,7,8,9,10
declare_var_vector_reg  Key0,18
declare_var_vector_reg  Key1,19
declare_var_vector_reg  Key2,21
declare_var_vector_reg  Key3,22
declare_var_vector_reg  Key4,23
declare_var_vector_reg  Key5,24
declare_var_vector_reg  Key6,25
declare_var_vector_reg  Key7,26
declare_var_vector_reg  Key8,27
declare_var_vector_reg  Key9,28
declare_var_vector_reg  Key10,29
declare_var_vector_reg  KeyLast0,30
declare_var_vector_reg  KeyLast1,31
declare_var_vector_reg  HashKey,20
declare_var_vector_reg  tmp0,16
declare_var_vector_reg  tmp1,17
declare_var_vector_reg  zero,14
declare_var_vector_reg  poly,15
declare_var_vector_reg  HashKeyIter,7   //only be used in prcomp
declare_var_vector_reg  AadHash,    7
declare_var_vector_reg  tmp2,6
declare_var_vector_reg  reg0,6
declare_var_vector_reg  reg1,5
declare_var_vector_reg  Ctr,4
declare_var_vector_reg  dat,3
declare_var_vector_reg  Partial,3
declare_var_vector_reg  Plain,3
declare_var_vector_reg  AadLen,3
declare_var_vector_reg  OrigIV,3
declare_var_vector_reg  Crypt,2
declare_var_vector_reg  one,1
declare_var_vector_reg  Len,0
.macro load_keys    key_addr:req
    ldr     qKey0,[\key_addr],16
    ld1     {vKey1.4s-vKey4.4s},[\key_addr],64
    ld1     {vKey5.4s-vKey8.4s},[\key_addr],64
    ld1     {vKey9.4s-vKeyLast1.4s},[\key_addr]
.endm
.set        stack_size,16
.macro  push_stack
    stp     d14,d15,[sp,-stack_size]!

.endm
.macro  pop_stack
    ldp     d14, d15, [sp], stack_size
.endm
#elif KEY_LEN==256
#define KEY_REGS 0,1,2,3,4,5,6,7,8,9,10,11,12
declare_var_vector_reg  Key0,17
declare_var_vector_reg  Key1,18
declare_var_vector_reg  Key2,19
declare_var_vector_reg  Key3,20
declare_var_vector_reg  Key4,21
declare_var_vector_reg  Key5,22
declare_var_vector_reg  Key6,23
declare_var_vector_reg  Key7,24
declare_var_vector_reg  Key8,25
declare_var_vector_reg  Key9,26
declare_var_vector_reg  Key10,27
declare_var_vector_reg  Key11,28
declare_var_vector_reg  Key12,29
declare_var_vector_reg  KeyLast0,30
declare_var_vector_reg  KeyLast1,31
declare_var_vector_reg  HashKey,16
declare_var_vector_reg  tmp0,15
declare_var_vector_reg  tmp1,14
declare_var_vector_reg  zero,13
declare_var_vector_reg  poly,12
declare_var_vector_reg  HashKeyIter,7   //only be used in prcomp
declare_var_vector_reg  AadHash,    7
declare_var_vector_reg  tmp2,6
declare_var_vector_reg  reg0,6
declare_var_vector_reg  reg1,5
declare_var_vector_reg  Ctr,4
declare_var_vector_reg  dat,3
declare_var_vector_reg  Partial,3
declare_var_vector_reg  Plain,3
declare_var_vector_reg  AadLen,3
declare_var_vector_reg  OrigIV,3
declare_var_vector_reg  Crypt,2
declare_var_vector_reg  one,1
declare_var_vector_reg  Len,0
.macro load_keys    key_addr:req
    ldr     qKey0,[\key_addr],16
    ld1     {vKey1.4s-vKey4.4s},[\key_addr],64
    ld1     {vKey5.4s-vKey8.4s},[\key_addr],64
    ld1     {vKey9.4s-vKey12.4s},[\key_addr],64
    ldp     qKeyLast0,qKeyLast1,[\key_addr]
.endm
.set        stack_size,32
.macro  push_stack
    stp     d12,d13,[sp,-stack_size]!
    stp     d14,d15,[sp,16]
.endm
.macro  pop_stack
    ldp     d14,d15,[sp,16]
    ldp     d12, d13, [sp], stack_size
.endm
#else
#error KEY_LEN undefined or NOT supported
#endif
.macro  init_const_regs tmp:req
    movi    vzero.4s,0
    mov     \tmp,0x87
    dup     vpoly.2d,\tmp
    mov     \tmp,1
    mov     vone.16b,vzero.16b
    ins     vone.4s[3],w\tmp
.endm
.macro aes_encrypt_round    block,key
    aese    v\block\().16b,vKey\key\().16b
    aesmc   v\block\().16b,v\block\().16b
.endm
.macro aes_encrypt_block    block:req
    .irp key,KEY_REGS
        aes_encrypt_round \block,\key
    .endr
    aese    v\block\().16b,vKeyLast0.16b
    eor     v\block\().16b,v\block\().16b,vKeyLast1.16b
.endm

.macro ghash_mult_128   r0:req,r1:req,a:req,b:req
    pmull       v\r0\().1q,v\a\().1d,v\b\().1d
    pmull2      v\r1\().1q,v\a\().2d,v\b\().2d
    ext         vtmp0.16b,v\b\().16b,v\b\().16b,8
    pmull       vtmp1.1q,v\a\().1d,vtmp0.1d
    pmull2      vtmp0.1q,v\a\().2d,vtmp0.2d
    eor         vtmp0.16b,vtmp0.16b,vtmp1.16b
    ext         vtmp1.16b,vzero.16b,vtmp0.16b,8
    eor         v\r0\().16b,v\r0\().16b,vtmp1.16b
    ext         vtmp1.16b,vtmp0.16b,vzero.16b,8
    eor         v\r1\().16b,v\r1\().16b,vtmp1.16b
.endm

.macro ghash_mult_rdc   r0:req,r1:req
    pmull2  vtmp0.1q,v\r1\().2d,vpoly.2d
    ext     vtmp1.16b,vtmp0.16b,vzero.16b,8
    eor     v\r1\().16b,v\r1\().16b,vtmp1.16b
    ext     vtmp1.16b,vzero.16b,vtmp0.16b,8
    eor     v\r0\().16b,v\r0\().16b,vtmp1.16b
    pmull   vtmp0.1q,v\r1\().1d,vpoly.1d
    eor     v\r0\().16b,v\r0\().16b,vtmp0.16b
.endm

.macro  ghash_mult  dest:req,GH:req,HK:req
    ghash_mult_128      \dest,reg1,\GH,\HK
    ghash_mult_rdc      \dest,reg1

.endm
.macro ghash_block  auth_dat:req,crypt:req,hashKey:req
    rbit        vtmp0.16b,v\crypt\().16b
    eor         v\auth_dat\().16b,v\auth_dat\().16b,vtmp0.16b
    ghash_mult  reg0,\auth_dat,\hashKey
    mov         v\auth_dat\().16b,vreg0.16b
.endm

/**Read data less than 16 */
.macro read_small_data  dest:req,src:req,size:req,tbl_adr:req,tmp1:req
    // size must less than 16
    ldr     q\tmp1,[\tbl_adr,\size,lsl 4]
    tbz     \size,3,1f
    ld1     {v\dest\().d}[0],[\src],8
1:
    tbz     \size,2,1f
    ld1     {v\dest\().s}[2],[\src],4
1:
    tbz     \size,1,1f
    ld1     {v\dest\().h}[6],[\src],2
1:
    tbz     \size,0,1f
    ld1     {v\dest\().b}[14],[\src],1
1:
    tbl     v\dest\().16b,{v\dest\().16b},v\tmp1\().16b
.endm
.macro read_small_data_start  dest:req,src:req,size:req,tbl_adr:req,tmp1:req
    adrp    \tbl_adr,lookup_table2
    add     \tbl_adr,\tbl_adr,:lo12:lookup_table2
    read_small_data \dest,\src,\size,\tbl_adr,\tmp1
.endm
.macro write_small_data  src:req,dest:req,size:req,tbl_adr:req,tmp1:req
    //size must less than 16
    ldr     q\tmp1,[\tbl_adr,\size,lsl 4]
    tbl     v\tmp1\().16b,{v\src\().16b},v\tmp1\().16b
    tbz     \size,3,1f
    st1     {v\tmp1\().d}[0],[\dest],8
1:
    tbz     \size,2,1f
    st1     {v\tmp1\().s}[2],[\dest],4
1:
    tbz     \size,1,1f
    st1     {v\tmp1\().h}[6],[\dest],2
1:
    tbz     \size,0,1f
    st1     {v\tmp1\().b}[14],[\dest],1
1:
.endm
.macro write_small_data_start  src:req,dest:req,size:req,tbl_adr:req,tmp1:req
    adrp    \tbl_adr,write_table
    add     \tbl_adr,\tbl_adr,:lo12:write_table
    write_small_data \src,\dest,\size,\tbl_adr,\tmp1
.endm

/**
void aes_gcm_precomp(struct gcm_key_data *key_data);
 */
    key_data        .req    x0
    hashkey_addr    .req    x1
    temp1           .req    x6
    wtemp1          .req    w6
START_FUNC(precomp,KEY_LEN,)
    push_stack
    add             hashkey_addr,key_data,15*16
    init_const_regs temp1
    load_keys       key_data
    mov             vHashKey.16b,vzero.16b
    aes_encrypt_block   HashKey
    rbit                vHashKey.16b,vHashKey.16b
    ext             vreg0.16b,vHashKey.16b,vHashKey.16b,8
    eor             vreg0.16b,vreg0.16b,vHashKey.16b
    str             qreg0,[hashkey_addr,8*16]
    mov             vHashKeyIter.16b,vHashKey.16b
    str             qHashKey,[hashkey_addr],16

    .rept   7
            ghash_mult      reg0,HashKeyIter,HashKey
            mov             vHashKeyIter.16b,vreg0.16b
            ext             vreg0.16b,vHashKeyIter.16b,vHashKeyIter.16b,8
            eor             vreg0.16b,vreg0.16b,vHashKeyIter.16b
            str             qreg0,[hashkey_addr,8*16]
            str             qHashKeyIter,[hashkey_addr],16
    .endr

    pop_stack
    ret
END_FUNC(precomp,KEY_LEN,)

/**
void aes_gcm_init(
    const struct gcm_key_data *key_data,
    struct gcm_context_data *context,
    uint8_t *iv,
    uint8_t const *aad,
    uint64_t aad_len,
    )
*/
    key_data        .req    x0
    context         .req    x1
    iv              .req    x2
    aad             .req    x3
    aad_len         .req    x4
    .unreq        hashkey_addr
    hashkey_addr    .req    x5
    temp0           .req    x7
    wtemp0          .req    w7
    temp1           .req    x6
START_FUNC(init,KEY_LEN,)
start_init:
    push_stack
    init_const_regs temp1
    add             hashkey_addr,key_data,15*16
    load_keys       key_data
    ldr             qHashKey,[hashkey_addr]
    mov             vAadHash.16b,vzero.16b
    stp             aad_len,xzr,[context,AAD_LEN_OFF]  //save in_length and aad_length
    str             xzr,[context,PARTIAL_BLOCK_LENGTH_OFF]     //clear partial_block_length
    /** Set orig_IV */
    ldr             wtemp0,[iv,8]
    ldr             temp1,[iv]
    movk            temp0,0x100,lsl 48
    stp             temp1,temp0,[context,ORIG_IV_OFF]
    /** Set current_counter, save as cpu order */
    ldr             qCtr,[context,48]
    rev32           vCtr.16b,vCtr.16b
    str             qCtr,[context,64]

start_aad_loop:
    cmp             aad_len,16-1
    bls             end_aad_loop
    ldr             qdat,[aad],16
    ghash_block     AadHash,dat,HashKey
    sub             aad_len,aad_len,16
    b               start_aad_loop
end_aad_loop:
    cbz             aad_len,exit_init
    read_small_data_start   dat,aad,aad_len,temp0,tmp0
    ghash_block     AadHash,dat,HashKey
exit_init:
    str             qAadHash,[context]   //save aad_hash
    pop_stack
    ret
END_FUNC(init,KEY_LEN,)


.macro aes_gcm_encrypt_block    ctr:req,auth:req,hashKey:req,in:req,out:req
    add         v\ctr\().4s,v\ctr\().4s,vone.4s //increase ctr 1
    rev32       vtmp0.16b,v\ctr\().16b
    aes_encrypt_block   tmp0
    eor         v\out\().16b,vtmp0.16b,v\in\().16b
    ghash_block \auth,\out,\hashKey
.endm

.macro aes_gcm_decrypt_block    ctr:req,auth:req,hashKey:req,in:req,out:req
    ghash_block \auth,\in,\hashKey
    add         v\ctr\().4s,v\ctr\().4s,vone.4s //increase ctr 1
    rev32       vtmp0.16b,v\ctr\().16b
    aes_encrypt_block   tmp0
    eor         v\out\().16b,vtmp0.16b,v\in\().16b
.endm

.macro gcm_enc_dec  reg,func
    cbz             len,3f
    init_const_regs temp1
    // update in_length
    ldr             temp0,[context,IN_LENGTH_OFF]
    add             temp0,temp0,len
    str             temp0,[context,IN_LENGTH_OFF]
    ldr             qAadHash,[context]
    ldr             qCtr,[context,CTR_OFF]

    // TODO: PRE process paritial block here
    ldr             partial_block_length,[context,PARTIAL_BLOCK_LENGTH_OFF]

    /** START OF PARTIAL BLOCK PROCESS */
    cbz             partial_block_length,2f

    ldr             qCrypt,[context,PARTIAL_BLOCK_ENC_KEY_OFF]
    /** temp2=read length */
    /** temp3=partial_block_length + read_length */
    mov             temp1,16
    sub             temp2,temp1,partial_block_length
    cmp             temp2,len
    csel            temp2,temp2,len,ls
    read_small_data_start   Plain,in,temp2,temp1,tmp1
    sub             len,len,temp2 //adjust len
    add             temp3,partial_block_length,temp2
    adrp            temp1,lookup_table1
    add             temp1,temp1,:lo12:lookup_table1
    ldr             qtmp2,[temp1]       //0xffs
    neg             temp3,temp3
    ldr             qtmp1,[temp1,temp2] //to end
    ldr             qtmp0,[temp1,temp3]
    tbx             vtmp2.16b,{vtmp1.16b},vtmp0.16b
    sub             temp3,partial_block_length,16
    add             partial_block_length,partial_block_length,temp2
    ldr             qtmp1,[temp1,temp3]

    .ifc \func,aes_gcm_encrypt_block
        tbl         vtmp0.16b,{vPlain.16b},vtmp2.16b
        eor         vCrypt.16b,vCrypt.16b,vtmp0.16b
        tbl         vtmp0.16b,{vCrypt.16b},vtmp1.16b

    .else
        tbl         vtmp0.16b,{vPlain.16b},vtmp2.16b
        eor         vtmp0.16b,vCrypt.16b,vtmp0.16b
        tbx         vCrypt.16b,{vPlain.16b},vtmp2.16b
        tbl         vtmp0.16b,{vtmp0.16b},vtmp1.16b
    .endif
    /**     output and update partial block */
    write_small_data_start  tmp0,out,temp2,temp1,tmp1
    ands            partial_block_length,partial_block_length,~16
    str             partial_block_length,[context,PARTIAL_BLOCK_LENGTH_OFF]
    str             qCrypt,[context,PARTIAL_BLOCK_ENC_KEY_OFF]
    bne             3f              //partial_block_length + len <16
    ghash_block     AadHash,Crypt,HashKey

    /** END OF PARTIAL BLOCK PROCESS */
    cbz             len,3f
2:
    cmp             len,16-1
    bls             1f
2:
    sub len,len,16
    ldr qPlain,[in],16
    \func   Ctr,AadHash,HashKey,Plain,Crypt
    str qCrypt,[out],16
    cmp len,15
    bhi 2b
1:
    cbz len,3f
    str len,[context,PARTIAL_BLOCK_LENGTH_OFF]
    add vCtr.4s,vCtr.4s,vone.4s
    rev32 vCrypt.16b,vCtr.16b
    aes_encrypt_block Crypt
    read_small_data_start   Plain,in,len,temp1,tmp1

    .ifc    \func,aes_gcm_encrypt_block
        eor     vCrypt.16b,vCrypt.16b,vPlain.16b
        write_small_data_start  Crypt,out,len,temp1,tmp1
    .else
        eor     vtmp0.16b,vPlain.16b,vCrypt.16b
        write_small_data_start  tmp0,out,len,temp1,tmp1
        adrp    temp1,lookup_table1
        add     temp1,temp1,:lo12:lookup_table1
        ldr     qtmp2,[temp1,len]
        neg     temp2,len
        sub     temp2,temp2,16
        ldr     qtmp1,[temp1,temp2]
        tbl     vtmp1.16b,{vtmp2.16b},vtmp1.16b
        tbx     vCrypt.16b,{vPlain.16b},vtmp1.16b
    .endif
    str     qCrypt,[context,PARTIAL_BLOCK_ENC_KEY_OFF]
3:
.endm

/**
void aes_gcm_enc_update(const struct gcm_key_data *key_data,
    struct gcm_context_data *context,
    uint8_t *out,
    uint8_t const *in,
    uint64_t len,

    AES_GCM_BLOCK_FN aes_gcm_block
    )
 */
    key_data        .req    x0
    context         .req    x1
    out             .req    x2
    in              .req    x3
    len             .req    x4
    .unreq        hashkey_addr
    hashkey_addr    .req    x5
    temp0           .req    x7
    wtemp0          .req    w7
    temp1           .req    x6
    partial_block_length    .req    x9
    partial_block           .req    x10
    temp2           .req    x11
    wtemp2          .req    w11
    temp3           .req    x12
    wtemp3          .req    w12
START_FUNC(enc,KEY_LEN,_update)
START_FUNC(enc,KEY_LEN,_update_nt)
    cbz len,4f
    push_stack
    add             hashkey_addr,key_data,15*16
    load_keys       key_data
    ldr             qHashKey,[hashkey_addr]
    gcm_enc_dec     2,aes_gcm_encrypt_block
    str qCtr,[context,CTR_OFF]
    str qAadHash,[context]
    pop_stack
4:
    ret
END_FUNC(enc,KEY_LEN,_update_nt)
END_FUNC(enc,KEY_LEN,_update)

/**
void aes_gcm_dec_update(const struct gcm_key_data *key_data,
    struct gcm_context_data *context,
    uint8_t *out,
    uint8_t const *in,
    uint64_t len,

    AES_GCM_BLOCK_FN aes_gcm_block
    )
 */
    key_data        .req    x0
    context         .req    x1
    out             .req    x2
    in              .req    x3
    len             .req    x4
    .unreq        hashkey_addr
    hashkey_addr    .req    x5
    temp0           .req    x7
    wtemp0          .req    w7
    temp1           .req    x6
    partial_block_length    .req    x9
    partial_block           .req    x10
    temp2           .req    x11
    wtemp2          .req    w11
    temp3           .req    x12
    wtemp3          .req    w12

START_FUNC(dec,KEY_LEN,_update)
START_FUNC(dec,KEY_LEN,_update_nt)
    cbz len,4f
    push_stack
    add             hashkey_addr,key_data,15*16
    load_keys       key_data
    ldr             qHashKey,[hashkey_addr]
    gcm_enc_dec     3,aes_gcm_decrypt_block
    str qCtr,[context,CTR_OFF]
    str qAadHash,[context]
    pop_stack
4:
    ret
END_FUNC(dec,KEY_LEN,_update)
END_FUNC(dec,KEY_LEN,_update_nt)

/**
void aes_gcm_*_*_finalize(
    const struct gcm_key_data *key_data,
    struct gcm_context_data *context,
    uint8_t *auth_tag,
    uint64_t auth_tag_len
    );
 */
    key_data        .req    x0
    context         .req    x1
    auth_tag        .req    x2
    auth_tag_len    .req    x3
    .unreq        hashkey_addr
    hashkey_addr    .req    x5
    temp0           .req    x7
    wtemp0          .req    w7
    temp1           .req    x6
    partial_block_length    .req    x9
    partial_block           .req    x10
    temp2           .req    x11
    wtemp2          .req    w11
    temp3           .req    x12
    wtemp3          .req    w12
 START_FUNC(enc,KEY_LEN,_finalize)
 START_FUNC(dec,KEY_LEN,_finalize)
    push_stack
    add             hashkey_addr,key_data,15*16
    load_keys       key_data
    ldr             qHashKey,[hashkey_addr]
    init_const_regs temp1
    ldr             partial_block_length,[context,PARTIAL_BLOCK_LENGTH_OFF]
    ldr             qAadHash,[context]
    /** Process Partial Block */
    cbz             partial_block_length,3f
    ldr             qPartial,[context,PARTIAL_BLOCK_ENC_KEY_OFF]
    adrp            temp0,lookup_table2
    neg             temp1,partial_block_length
    add             temp0,temp0,:lo12:lookup_table2
    ldr             qtmp0,[temp0,temp1]
    tbx             vPartial.16b,{vzero.16b},vtmp0.16b
    ghash_block     AadHash,Partial,HashKey
3:  /** END of Partial Block process */
    /** load len and aad_len */
    ldr             qAadLen,[context,AAD_LEN_OFF]
    shl             vAadLen.2d,vAadLen.2d,3
    rev64           vAadLen.16b,vAadLen.16b
    ghash_block     AadHash,AadLen,HashKey
    /** cal orig_IV */
    ldr             qOrigIV,[context,ORIG_IV_OFF]
    rbit            vAadHash.16b,vAadHash.16b
    aes_encrypt_block   OrigIV
    eor             vAadHash.16b,vAadHash.16b,vOrigIV.16b

    cmp         auth_tag_len,16
    bne         1f
    /** most likely auth_tag_len=16 */
    str         qAadHash,[auth_tag]
    pop_stack
    ret
1:  /** auth_tag_len=12 */
    cmp         auth_tag_len,12
    bne         1f
    str         dAadHash,[auth_tag],8
    st1         {vAadHash.s}[2],[auth_tag]
    pop_stack
    ret
1:  /** auth_tag_len=8 */
    str         dAadHash,[auth_tag]
    pop_stack
    ret
END_FUNC(dec,KEY_LEN,_finalize)
END_FUNC(enc,KEY_LEN,_finalize)

.macro  aes_gcm_enc_dec func:req
    /** Init  */
    ldp             auth_tag,auth_tag_len,[sp]
    push_stack
    init_const_regs temp1
    add             hashkey_addr,key_data,15*16
    load_keys       key_data
    ldr             qHashKey,[hashkey_addr]
    ins             vLen.d[0],aad_len
    ins             vLen.d[1],len
    /** Set IV and current counter */
    ldr             wtemp0,[iv,8]
    ldr             temp1,[iv]              //iv free
    movk            temp0,0x100,lsl 48
    ins             vCtr.d[0],temp1
    ins             vCtr.d[1],temp0
    mov             vAadHash.16b,vzero.16b
    rev32           vCtr.16b,vCtr.16b

2:  /** START OF  Cacl AAD Hash */
    cmp             aad_len,16-1
    bls             1f
    ldr             qdat,[aad],16
    ghash_block     AadHash,dat,HashKey
    sub             aad_len,aad_len,16
    b               2b
1:
    cbz             aad_len,2f
    read_small_data_start   dat,aad,aad_len,temp0,tmp1
    ghash_block     AadHash,dat,HashKey
2:  /** END OF Cacl AAD Hash (aad_len and aad free )*/
    cbz             len,3f

    /** START OF MAIN ENC/DEC LOOP */
    cmp             len,16-1
    bls             1f
2:
    sub     len,len,16
    ldr     qPlain,[in],16
    \func   Ctr,AadHash,HashKey,Plain,Crypt
    str     qCrypt,[out],16
    cmp     len,15
    bhi     2b
    cbz     len,3f
1:
    /** Start of  Block Less than 16 */
    add     vCtr.4s,vCtr.4s,vone.4s
    rev32   vtmp0.16b,vCtr.16b
    aes_encrypt_block   tmp0
    read_small_data_start Plain,in,len,temp1,tmp1
    /** clear crypt ctr (len-16) B  */
    neg     temp0,len
    ldr     qtmp1,[temp1,temp0]
    tbx     vtmp0.16b,{vzero.16b},vtmp1.16b
    eor     vCrypt.16b,vtmp0.16b,vPlain.16b
    .ifc     \func,aes_gcm_encrypt_block
        ghash_block     AadHash,Crypt,HashKey
    .else
        ghash_block     AadHash,Plain,HashKey
    .endif
    write_small_data_start  Crypt,out,len,temp1,tmp1
3:  /** END OF MAIN ENC/DEC LOOP */
    /** ghash len and aad_len */
    shl             vLen.2d,vLen.2d,3
    rev64           vLen.16b,vLen.16b
    ghash_block     AadHash,Len,HashKey

    mov             wtemp0,1
    ins             vCtr.4s[3],wtemp0
    rbit            vAadHash.16b,vAadHash.16b
    rev32           vCtr.16b,vCtr.16b
    aes_encrypt_block   Ctr
    eor             vAadHash.16b,vAadHash.16b,vCtr.16b
    /** output auth_tag */
    cmp         auth_tag_len,16
    bne         1f
    /** most likely auth_tag_len=16 */
    str         qAadHash,[auth_tag]
    pop_stack
    ret
1:  /** auth_tag_len=12 */
    cmp         auth_tag_len,12
    bne         1f
    str         dAadHash,[auth_tag],8
    st1         {vAadHash.s}[2],[auth_tag]
    pop_stack
    ret
1:  /** auth_tag_len=8 */
    str         dAadHash,[auth_tag]
    pop_stack
    ret
.endm

/**
void aes_gcm_enc(
    const struct gcm_key_data *key_data,   //!< GCM expanded key data
    struct gcm_context_data *context_data, //!< GCM operation context data
    uint8_t *out,         //!< Ciphertext output. Encrypt in-place is allowed
    uint8_t const *in,    //!< Plaintext input
    uint64_t len,         //!< Length of data in Bytes for encryption
    uint8_t *iv,          //!< iv pointer to 12 byte IV structure.
                          //!< Internally, library concates 0x00000001 value to it.
    uint8_t const *aad,   //!< Additional Authentication Data (AAD)
    uint64_t aad_len,     //!< Length of AAD
    uint8_t *auth_tag,    //!< Authenticated Tag output
    uint64_t auth_tag_len //!< Authenticated Tag Length in bytes (must be a multiple of 4 bytes).
                          //!< Valid values are 16 (most likely), 12 or 8
    );

 */
    key_data        .req    x0
    context         .req    x1
    out             .req    x2
    in              .req    x3
    len             .req    x4
    .unreq  iv
    iv              .req    x5      //iv will free after init
    .unreq  aad
    aad             .req    x6
    .unreq  aad_len
    aad_len         .req    x7
    .unreq  auth_tag
    auth_tag        .req    x9
    .unreq  auth_tag_len
    auth_tag_len    .req    x10
    .unreq        hashkey_addr
    hashkey_addr    .req    x11
    .unreq  temp0
    temp0           .req    x12
    .unreq  wtemp0
    wtemp0          .req    w12
    .unreq  temp1
    temp1           .req    x13
    .unreq  wtemp1
    wtemp1           .req    w13
    .unreq  temp2
    temp2           .req    x14
    .unreq  wtemp2
    wtemp2          .req    w14
    .unreq  temp3
    temp3           .req    x15
    .unreq  wtemp3
    wtemp3          .req    w15
    .unreq  partial_block
    partial_block   .req    x5

START_FUNC(enc,KEY_LEN,)
START_FUNC(enc,KEY_LEN,_nt)
    aes_gcm_enc_dec aes_gcm_encrypt_block
END_FUNC(enc,KEY_LEN,)
END_FUNC(enc,KEY_LEN,_nt)

START_FUNC(dec,KEY_LEN,)
START_FUNC(dec,KEY_LEN,_nt)
    aes_gcm_enc_dec aes_gcm_decrypt_block
END_FUNC(dec,KEY_LEN,)
END_FUNC(dec,KEY_LEN,_nt)

/**const data */
lookup_table:
    .byte      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15
rotate_table:
    .byte      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15
lookup_table1:
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
lookup_table2:
    .byte      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15
    .byte   0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x0c,0x0d,0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x08,0x09,0x0a,0x0b,0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x08,0x09,0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0c,0x0d,0x0e,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0e,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0xff,0xff
write_table:
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0xff,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0x02,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0x02,0x03,0xff,0xff,0xff,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0x02,0x03,0xff,0xff,0x04,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0x02,0x03,0x04,0x05,0xff,0xff
    .byte   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff,0xff,0xff,0x08,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff,0x08,0x09,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff,0x08,0x09,0x0a,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0xff,0xff,0x0c,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0xff,0xff
    .byte   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0xff

