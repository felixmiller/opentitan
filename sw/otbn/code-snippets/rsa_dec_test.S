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

.text
start:
bn.xor w0, w0, w0
JAL x1, modload
JAL x1, modexp
ecall

d0inv:
  bn.xor    w0, w0, w0
  bn.addi   w0, w0, 1
  bn.mov    w29, w0
  loopi     256, 13
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
    bn.and    w1, w1, w0
    bn.or     w29, w29, w1
    bn.add    w0, w0, w0
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
  ret

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
  ret

.data

/* dmem cell 0: pointers */
/* in */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000004c0
.word 0x000002c0
.word 0x000004c0
.word 0x00000004
.word 0x00000003

/* dmem cell 1: pointers */
/* sqr */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000008e0
.word 0x000008e0
.word 0x000008e0
.word 0x00000004
.word 0x00000003

/* dmem cell 2: pointers */
/* mul */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000004c0
.word 0x000008e0
.word 0x000008e0
.word 0x00000004
.word 0x00000003

/* dmem cell 1: pointers */
/* out */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000008e0
.word 0x000006c0
.word 0x000008e0
.word 0x00000004
.word 0x00000003

/* modulus in dmem cell 4 */
.quad 0xb6e64c3bc28cf49f
.quad 0x34ab89fea21417f1
.quad 0xe9289a03e4d4c752
.quad 0xafb68c05c8aa371c

.quad 0xa62c908d893c882e
.quad 0xea5bb198d23f4ebf
.quad 0xcfcc4b48db6f076f
.quad 0x7bda03fc75a24aa4

.quad 0xbc7c20bccb5adf60
.quad 0x3ba5d46d8ea4f2fe
.quad 0x7f29299521536a4e
.quad 0xc8033b94aafd0e56

.quad 0xa3998c2e127ca9e8
.quad 0xc39b1e20ecf3ecf6
.quad 0x5affc57cdc59f4e7
.quad 0x962be2990a4536b4

/* encrypted msg */
/* skip to 1216 */
.skip 960
.quad 0x7ae96741e0e14a9b
.quad 0xcda13a474a430036
.quad 0x3810cd5179524410
.quad 0x686f3abe3b47425f

.quad 0xbfa8b28491dff899
.quad 0xa66cf53c0539e396
.quad 0x0d595811bcdc315a
.quad 0x5b9dce330a522e08

.quad 0x587a618e6fde2d48
.quad 0x4affcc626b4c0c56
.quad 0x991f39d06a88ead2
.quad 0x3c0d662639f88b9a

.quad 0x82f3f1f6a3fe6181
.quad 0x938bfd7b43f4ed0b
.quad 0x8ade6cc060de8b63
.quad 0x35f506d191f560d7

/* priv exponent */
/* skip to 1728 */
.skip 384
.quad 0x24a2614b93a8cd95
.quad 0x6dfc48e4eeb788b3
.quad 0x41146c79ca97cdc4
.quad 0xc386c827f4ca744b

.quad 0xae51440fd9ddaef3
.quad 0x9ebad71b9741739d
.quad 0xfbd588489a7a2bfd
.quad 0x17f60ed913464f06

.quad 0x581ccd6c1d63a0b9
.quad 0x35a9ec64951579d6
.quad 0xdd2f62e8c3a08e32
.quad 0x01ca5c4ec3739e4a

.quad 0xf9dacc793a107e7d
.quad 0x5d21e91049ecbe20
.quad 0x511778ce9550ecb5
.quad 0x41b468dc42209f7b

/* Expected decrypted Message in DMEM:
[2303..2272]: 0x656e637279707420616e642064656372797074207468697320666f72206d653f
[2335..2304]: 0x0000000000000000000048656c6c6f206269676e756d2c2063616e20796f7520
[2367..2336]: 0x0000000000000000000000000000000000000000000000000000000000000000
[2399..2368]: 0x0000000000000000000000000000000000000000000000000000000000000000
*/
