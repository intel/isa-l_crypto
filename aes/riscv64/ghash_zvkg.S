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

/*
 * Internal RISC-V ZVKG GHASH helper for isa-l_crypto GCM wrappers.
 *
 * Uses 4-block parallel aggregation for throughput: four independent
 * accumulators each multiplied by H^4 per step, with the final 4-block
 * group using descending powers [H^4, H^3, H^2, H] for correctness.
 * This is VLEN-independent (always uses m1 with vl=4, one block = 4×e32).
 *
 * The KEY parameter points to a contiguous table of four 16-byte GF(2^128)
 * elements: H at offset 0, H^2 at +16, H^3 at +32, H^4 at +48.
 * This matches the layout of isal_gcm_key_data.shifted_hkey_1..4 as
 * computed by the base GCM precomp using standard GF(2^128) multiplication.
 *
 * void ghash_zvkg(uint8_t *Xi, const uint8_t *H, const uint8_t *data,
 *                 uint64_t nblocks);
 */

#if HAVE_RISCV_ZVK

.text
	.option arch, +v, +zvkg

#define Xi	a0
#define Htable	a1
#define DATA	a2
#define NBLOCKS	a3

.macro FUNC_START name
	.global \name
	.type   \name, %function
\name:
.endm

.macro FUNC_END name
	.size \name, .-\name
.endm

/*
 * Register usage:
 *   v1        – running Xi accumulator (also final result)
 *   v2        – H  (Htable[0])
 *   v5        – H^4 (Htable[48])
 *   v6        – H^3 (Htable[32])
 *   v7        – H^2 (Htable[16])
 *   v8-v11    – four input blocks (scratch)
 *   v20-v23   – four independent accumulators for the parallel path
 */
FUNC_START ghash_zvkg
	beqz		NBLOCKS, .Lret		/* nothing to do */

	vsetivli	zero, 4, e32, m1, ta, ma
	vle32.v		v1, (Xi)		/* v1 = Xi */
	vle32.v		v2, (Htable)		/* v2 = H */

	li		t0, 4
	bltu		NBLOCKS, t0, .Lstep	/* nblocks < 4: single-block path */

	/* --- 4-block aggregation path --- */
	addi		t0, Htable, 48
	vle32.v		v5, (t0)		/* v5 = H^4 */
	addi		t0, Htable, 32
	vle32.v		v6, (t0)		/* v6 = H^3 */
	addi		t0, Htable, 16
	vle32.v		v7, (t0)		/* v7 = H^2 */

	vmv.v.v		v20, v1			/* lane 0 = Xi */
	vmv.v.i		v21, 0			/* lane 1 = 0 */
	vmv.v.i		v22, 0			/* lane 2 = 0 */
	vmv.v.i		v23, 0			/* lane 3 = 0 */

	li		t0, 8
	bltu		NBLOCKS, t0, .Llast_4x	/* nblocks < 8: skip main loop */

	/*
	 * Main loop: process groups of 4 blocks with all lanes using H^4.
	 * Each lane independently accumulates every 4th block.
	 * Runs while nblocks >= 8 so the last 4 blocks are processed
	 * by .Llast_4x with the correct descending-power multipliers.
	 */
.Lghash_4x:
	vle32.v		v8,  (DATA)
	addi		DATA, DATA, 16
	vle32.v		v9,  (DATA)
	addi		DATA, DATA, 16
	vle32.v		v10, (DATA)
	addi		DATA, DATA, 16
	vle32.v		v11, (DATA)
	addi		DATA, DATA, 16
	addi		NBLOCKS, NBLOCKS, -4
	vghsh.vv	v20, v5, v8		/* lane 0: (v20 ^ v8) * H^4 */
	vghsh.vv	v21, v5, v9		/* lane 1: (v21 ^ v9) * H^4 */
	vghsh.vv	v22, v5, v10		/* lane 2: (v22 ^ v10) * H^4 */
	vghsh.vv	v23, v5, v11		/* lane 3: (v23 ^ v11) * H^4 */
	li		t0, 8
	bgeu		NBLOCKS, t0, .Lghash_4x

	/*
	 * Last 4-block group: multiply with [H^4, H^3, H^2, H] so the
	 * combined result equals the correct GHASH polynomial evaluation.
	 */
.Llast_4x:
	vle32.v		v8,  (DATA)
	addi		DATA, DATA, 16
	vle32.v		v9,  (DATA)
	addi		DATA, DATA, 16
	vle32.v		v10, (DATA)
	addi		DATA, DATA, 16
	vle32.v		v11, (DATA)
	addi		DATA, DATA, 16
	addi		NBLOCKS, NBLOCKS, -4
	vghsh.vv	v20, v5, v8		/* lane 0: * H^4 */
	vghsh.vv	v21, v6, v9		/* lane 1: * H^3 */
	vghsh.vv	v22, v7, v10		/* lane 2: * H^2 */
	vghsh.vv	v23, v2, v11		/* lane 3: * H   */

	/* Reduce four lanes: v1 = v20 ^ v21 ^ v22 ^ v23 */
	vxor.vv		v20, v20, v21
	vxor.vv		v20, v20, v22
	vxor.vv		v20, v20, v23
	vmv.v.v		v1, v20

	beqz		NBLOCKS, .Ldone		/* no tail blocks */

	/* Single-block tail for remaining 1-3 blocks */
.Lstep:
	vle32.v		v3, (DATA)
	addi		DATA, DATA, 16
	addi		NBLOCKS, NBLOCKS, -1
	vghsh.vv	v1, v2, v3
	bnez		NBLOCKS, .Lstep

.Ldone:
	vse32.v		v1, (Xi)
.Lret:
	ret
FUNC_END ghash_zvkg

#endif
