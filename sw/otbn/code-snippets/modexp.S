/* Copyright lowRISC Contributors.
 * Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.dcrypto file.
 *
 * Derived from code in
 *
 *	https://chromium.googlesource.com/chromiumos/platform/ec/+/refs/heads/cr50_stab/chip/g/dcrypto/dcrypto_bn.c
 *
 */

/**
 * Precomputation of a constant m0' for Montgomery modular arithmetic
 *
 * Word-wise montgomery modular arithmetic requires a quantity m0' to be
 * precomputed once per modulus m. m0' is the negative of the
 * modular multiplicative inverse of the lowest limb m0 of the modulus m, in the
 * field GF(2^w), where w is the number of bits per limb. w is set to 256
 * in this subroutine.
 *
 * Returns: m0' = -m0^(-1) mod 2^256
 *          with m_0 being the lowest limb of the modulus m
 *
 * This subroutine implements the Dusse-Kaliski method for computing the
 * multiplicative modular inverse when the modulus is of the form 2^k.
 * [Dus] DOI https://doi.org/10.1007/3-540-46877-3_21 section 3.2
 *       (Algorithm "Modular Inverse" on p. 235)
 *
 * Flags: When leaving this subroutine, flags of FG0 depend on a
 *        the final subtraction and can be used if needed.
 *        FG0.M, FG0.L, FG0.Z depend directly on the value of the result m0'.
 *        FG0.C is always set.
 *        FG1 is not modified in this subroutine.
 *
 * @param[in]  w28: m0, the lowest 256 bit limb of the modulus m
 * @param[in]  w31: all-zero.
 * @param[out] w29: m0', negative of inverse of m0 in GF(2^256)
 *
 * Clobbered registers: w0, w1, w29
 * Clobbered flag groups: FG0
 */
d0inv:
  /* w0 keeps track of loop iterations in one-hot encoding, i.e.
     w0 = 2^i in the loop body below and initialized here with w0 = 1
     It is used for both the comparison in step 4 of [Dus] and the
     addition in step 6 of [Dus] */
  bn.xor    w0, w0, w0
  bn.addi   w0, w0, 1

  /* according to [Dus] the result variable y has to be initialized with 1 */
  /* w29 = y_0 = 1 */
  bn.mov    w29, w0

  /* Iterate over all 256 bits of m0.
     i refers to the loop cycle 0..255 in the loop body below. */
  loopi     256, 13

    /* y_i <= m*y_{i-1] */
    bn.mulqacc.z          w28.0, w29.0,  0
    bn.mulqacc            w28.1, w29.0, 64
    bn.mulqacc.so   w1.L, w28.0, w29.1, 64
    bn.mulqacc            w28.2, w29.0,  0
    bn.mulqacc            w28.1, w29.1,  0
    bn.mulqacc            w28.0, w29.2,  0
    bn.mulqacc            w28.3, w29.0, 64
    bn.mulqacc            w28.2, w29.1, 64
    bn.mulqacc            w28.1, w29.2, 64
    bn.mulqacc.so   w1.U, w28.0, w29.3, 64

  /* This checks if w1 = y_i = m0*y_(i-1) < 2^(i-1) mod 2^i
     Due to the mathematical properties it can be shown that y_i at this point,
     is either 1 or (10..0..01)_(i). Therefore, just probing the i_th bit is
     the same as the full compare. */
    bn.and    w1, w1, w0

    /* Compute
       y_i=w29 <= w1=m0*y_(i-1) < 2^(i-1) mod 2^i y_i ? : y_{i-1}+2^i : y_{i-1}
       there can't be overlaps => or'ing is as good as adding */
    bn.or     w29, w29, w1

    /* double w0 (w0 <= w0 << 1) i.e. w0=2^i */
    bn.add    w0, w0, w0

  /* finally, compute m0' (negative of inverse)
     w29 = m0' = -(m0^-1) mod 2^256 = -y_255 = 0 - y_255 = w31 - w29 */
  bn.sub    w29, w31, w29

  ret

selcxSub:
  li         x8, 5
  li        x10, 3
  li        x11, 2
  lw        x16, 0(x0)
  bn.add    w31, w31, w31
  loop      x30, 5
  bn.lid    x10, 0(x16++)
  bn.movr   x11, x8
  bn.subb   w4, w2, w3
  bn.sel    w3, w4, w2, FG1.C
  bn.movr   x8++, x10
  ret

computeRR:
  bn.xor    w31, w31, w31
  li        x3, 0
  bn.lid    x3, 0(x0)
  lw        x16, 0(x0)
  lw        x17, 4(x0)
  lw        x18, 8(x0)
  lw        x19, 12(x0)
  lw        x20, 16(x0)
  lw        x21, 20(x0)
  lw        x22, 24(x0)
  lw        x23, 28(x0)
  bn.xor    w3, w3, w3
  slli      x24, x22, 8
  li        x8, 5
  li        x10, 3
  bn.xor    w3, w3, w3
  loop      x30, 1
  bn.movr   x8++, x10
  bn.sub    w3, w31, w0, FG1
  jal       x1, selcxSub
  loop      x24, 16
  li        x8, 5
  bn.sub    w3, w3, w3, FG1
  loop      x30, 3
  bn.movr   x11, x8
  bn.addc   w2, w2, w2, FG1
  bn.movr   x8++, x11
  jal       x1, selcxSub
  li        x8, 5
  lw        x16, 0(x0)
  bn.sub    w3, w3, w3, FG1
  loop      x30, 3
  bn.lid    x10, 0(x16++)
  bn.movr   x11, x8++
  bn.cmpb   w3, w2, FG1
  jal       x1, selcxSub
  li        x0, 0
  li        x8, 5
  loop      x30, 2
  bn.sid    x8, 0(x18++)
  addi      x8, x8, 1
  ret

dmXd0:
  bn.mulqacc.z          w30.0, w25.0,  0
  bn.mulqacc            w30.1, w25.0, 64
  bn.mulqacc.so  w27.L, w30.0, w25.1, 64
  bn.mulqacc            w30.2, w25.0,  0
  bn.mulqacc            w30.1, w25.1,  0
  bn.mulqacc            w30.0, w25.2,  0
  bn.mulqacc            w30.3, w25.0, 64
  bn.mulqacc            w30.2, w25.1, 64
  bn.mulqacc            w30.1, w25.2, 64
  bn.mulqacc.so  w27.U, w30.0, w25.3, 64
  bn.mulqacc            w30.3, w25.1,  0
  bn.mulqacc            w30.2, w25.2,  0
  bn.mulqacc            w30.1, w25.3,  0
  bn.mulqacc            w30.3, w25.2, 64
  bn.mulqacc.so  w26.L, w30.2, w25.3, 64
  bn.mulqacc.so  w26.U, w30.3, w25.3,  0
  ret

dmXa:
  bn.mulqacc.z          w30.0, w2.0,  0
  bn.mulqacc            w30.1, w2.0, 64
  bn.mulqacc.so  w27.L, w30.0, w2.1, 64
  bn.mulqacc            w30.2, w2.0,  0
  bn.mulqacc            w30.1, w2.1,  0
  bn.mulqacc            w30.0, w2.2,  0
  bn.mulqacc            w30.3, w2.0, 64
  bn.mulqacc            w30.2, w2.1, 64
  bn.mulqacc            w30.1, w2.2, 64
  bn.mulqacc.so  w27.U, w30.0, w2.3, 64
  bn.mulqacc            w30.3, w2.1,  0
  bn.mulqacc            w30.2, w2.2,  0
  bn.mulqacc            w30.1, w2.3,  0
  bn.mulqacc            w30.3, w2.2, 64
  bn.mulqacc.so  w26.L, w30.2, w2.3, 64
  bn.mulqacc.so  w26.U, w30.3, w2.3,  0
  ret

mma_sub_cx:
  loop      x30, 6
  bn.lid    x13, 0(x16++)
  bn.movr   x12, x8
  bn.subb   w29, w30, w24
  bn.movr   x8, x13
  bn.sel    w24, w29, w30, FG1.C
  bn.movr   x8++, x13
  ret

mma:
  li        x12, 30
  li        x13, 24
  li         x8,  4
  li        x10,  4
  bn.lid    x12, 0(x19++)
  jal x1,   dmXa
  bn.movr   x13, x8++
  bn.add    w30, w27, w24
  bn.addc   w29, w26, w31
  bn.mov    w25, w3
  jal       x1, dmXd0
  bn.mov    w25, w27
  bn.mov    w28, w26
  bn.mov    w24, w30
  bn.lid    x12, 0(x16++)
  jal x1,   dmXd0
  bn.add    w27, w27, w24
  bn.addc   w28, w26, w31
  loop      x31, 14
  bn.lid    x12, 0(x19++)
  jal       x1, dmXa
  bn.movr   x13, x8++
  bn.add    w27, w27, w24
  bn.addc   w26, w26, w31
  bn.add    w24, w27, w29
  bn.addc   w29, w26, w31
  bn.lid    x12, 0(x16++)
  jal       x1, dmXd0
  bn.add    w27, w27, w24
  bn.addc   w26, w26, w31
  bn.add    w24, w27, w28, FG1
  bn.movr   x10++, x13
  bn.addc   w28, w26, w31, FG1
  bn.addc   w24, w29, w28, FG1
  bn.movr   x10++, x13
  lw        x16, 0(x0)
  lw        x19, 12(x0)
  li        x8, 4
  li        x10, 4
  li        x12, 30
  li        x13, 24
  jal       x1, mma_sub_cx
  nop
  ret

setupPtrs:
  lw        x16, 0(x0)
  lw        x17, 4(x0)
  lw        x18, 8(x0)
  lw        x19, 12(x0)
  lw        x20, 16(x0)
  lw        x21, 20(x0)
  lw        x22, 24(x0)
  lw        x23, 28(x0)
  lw        x24, 0(x0)
  lw        x25, 4(x0)
  lw        x26, 8(x0)
  lw        x27, 12(x0)
  lw        x28, 16(x0)
  lw        x29, 20(x0)
  lw        x30, 24(x0)
  lw        x31, 28(x0)
  bn.mov    w1, w31
  li         x8, 4
  li         x9, 3
  li        x10, 4
  li        x11, 2
  ret

mulx:
  li        x3, 0
  bn.lid    x3, 0(x0)
  jal       x1, setupPtrs
  bn.lid    x9, 0(x17)
  bn.mov    w2, w31
  loop      x30, 1
  bn.movr   x10++, x11
  li        x10, 4
  loop      x30, 8
  bn.lid    x11, 0(x20++)
  add       x4, x16, x0
  add       x5, x19, x0
  add       x6, x20, x0
  jal       x1, mma
  add       x16, x4, x0
  add       x19, x5, x0
  add       x20, x6, x0
  li        x8, 4
  loop      x30, 2
  bn.sid    x8, 0(x21++)
  addi      x8, x8, 1
  li        x8, 4
  ret

mm1_sub_cx:
  loop      x30, 5
  bn.lid    x9, 0(x16++)
  bn.movr   x11, x8++
  bn.subb   w3, w2, w3
  bn.sel    w2, w3, w2, FG1.C
  bn.sid    x11, 0(x21++)
  ret

mul1_exp:
  bn.lid    x9, 0(x17)
  bn.mov    w2, w31
  loop      x30, 1
  bn.movr   x10++, x11
  bn.xor    w2, w2, w2
  bn.addi   w2, w2, 1
  addi      x6, x16, 0
  addi      x7, x19, 0
  loop      x30, 4
  addi      x16, x6, 0
  addi      x19, x7, 0
  jal       x1, mma
  bn.mov    w2, w31
  addi      x16, x6, 0
  addi      x19, x7, 0
  bn.sub    w2, w2, w2, FG1
  loop      x30, 3
  bn.lid    x9, 0(x16++)
  bn.movr   x11, x8++
  bn.cmpb   w3, w2, FG1
  li         x8, 4
  li        x10, 4
  addi      x16, x6, 0
  addi      x19, x7, 0
  jal       x1, mm1_sub_cx
  addi      x16, x6, 0
  addi      x19, x7, 0
  ret

mul1:
  li        x3, 0
  bn.lid    x3, 0(x0)
  jal       x1, setupPtrs
  jal       x1, mul1_exp
  ecall

sqrx_exp:
  lw        x16, 32(x0)
  lw        x17, 36(x0)
  lw        x18, 40(x0)
  lw        x19, 44(x0)
  lw        x20, 48(x0)
  lw        x21, 52(x0)
  lw        x22, 56(x0)
  lw        x23, 60(x0)
  bn.lid    x9, 0(x17)
  bn.mov    w2, w31
  loop      x30, 1
  bn.movr   x10++, x11
  lw        x10, 8(x0)
  loop      x30, 8
  bn.lid    x11, 0(x20++)
  addi      x5, x20, 0
  addi      x6, x16, 0
  addi      x7, x19, 0
  jal       x1, mma
  addi      x20, x5, 0
  addi      x16, x6, 0
  addi      x19, x7, 0
  li        x10, 4
  li         x8, 4
  loop      x30, 2
  bn.sid    x8, 0(x21++)
  addi      x8, x8, 1
  li         x8, 4
  li        x10, 4
  lw        x12, 16(x0)
  lw        x13, 20(x0)
  ret

mulx_exp:
  lw        x16, 64(x0)
  lw        x17, 68(x0)
  lw        x18, 72(x0)
  lw        x19, 76(x0)
  lw        x20, 80(x0)
  lw        x21, 84(x0)
  lw        x22, 88(x0)
  lw        x23, 92(x0)
  bn.lid    x9, 0(x17)
  bn.mov    w2, w31
  loop      x30, 1
  bn.movr   x10++, x11
  li         x8, 4
  li        x10, 4
  lw        x12, 16(x0)
  lw        x13, 20(x0)
  loop      x30, 8
  bn.lid    x11, 0(x20++)
  addi      x5, x20, 0
  addi      x6, x16, 0
  addi      x7, x19, 0
  jal       x1, mma
  addi      x20, x5, 0
  addi      x16, x6, 0
  addi      x19, x7, 0
  li        x8, 4
  li        x10, 4
  lw        x12, 16(x0)
  lw        x13, 20(x0)
  ret

selOutOrC:
  loop      x30, 6
  bn.lid    x9, 0(x21)
  bn.sid    x11, 0(x21)
  bn.movr   x11, x8++
  bn.mov    w0, w2
  bn.sel    w2, w0, w3, C
  bn.sid    x11, 0(x21++)
  ret

modexp:
  jal       x1, mulx
  lw        x16, 96(x0)
  lw        x17, 100(x0)
  lw        x18, 104(x0)
  lw        x19, 108(x0)
  lw        x20, 112(x0)
  lw        x21, 116(x0)
  lw        x22, 120(x0)
  lw        x23, 124(x0)
  bn.sub    w2, w2, w2
  loop      x30, 3
  bn.lid    x11, 0(x16++)
  bn.subb   w2, w31, w2
  bn.sid    x11, 0(x21++)
  slli      x24, x22, 8
  loop      x24, 17
  jal       x1, sqrx_exp
  jal       x1, mulx_exp
  lw        x16, 96(x0)
  lw        x17, 100(x0)
  lw        x18, 104(x0)
  lw        x19, 108(x0)
  lw        x20, 112(x0)
  lw        x21, 116(x0)
  lw        x22, 120(x0)
  lw        x23, 124(x0)
  bn.add    w2, w2, w2
  loop      x30, 3
  bn.lid    x11, 0(x20)
  bn.addc   w2, w2, w2
  bn.sid    x11, 0(x20++)
  jal       x1, selOutOrC
  nop
  li        x3, 0
  bn.lid    x3, 96(x0)
  lw        x16, 96(x0)
  lw        x17, 100(x0)
  lw        x18, 104(x0)
  lw        x19, 108(x0)
  lw        x20, 112(x0)
  lw        x21, 116(x0)
  lw        x22, 120(x0)
  lw        x23, 124(x0)
  jal       x1, mul1_exp
  ecall

modload:
  bn.xor   w31, w31, w31
  li       x3, 0
  bn.lid   x3, 0(x0)
  lw       x16, 0(x0)
  lw       x17, 4(x0)
  lw       x18, 8(x0)
  lw       x19, 12(x0)
  lw       x20, 16(x0)
  lw       x21, 20(x0)
  lw       x22, 24(x0)
  lw       x23, 28(x0)
  lw       x24, 0(x0)
  lw       x25, 4(x0)
  lw       x26, 8(x0)
  lw       x27, 12(x0)
  lw       x28, 16(x0)
  lw       x29, 20(x0)
  lw       x30, 24(x0)
  lw       x31, 28(x0)
  li       x8, 28
  li       x9, 29
  lw       x10, 8(x0)
  lw       x11, 12(x0)
  lw       x12, 16(x0)
  lw       x13, 20(x0)
  lw       x14, 24(x0)
  lw       x15, 28(x0)
  bn.lid   x8, 0(x16)
  jal      x1, d0inv
  bn.sid   x9, 0(x17)
  jal      x1, computeRR
  ecall
