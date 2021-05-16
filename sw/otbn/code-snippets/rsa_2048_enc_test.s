/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */


.text

/**
 * Standalone RSA 2048 encrypt
 *
 * Uses OTBN modexp bignum lib to encrypt the message from the .data segment
 * in this file with the public key consisting of e=65537 and modulus from
 * .data segment in this file.
 *
 * Copies the encrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
run_rsa_2048_enc:

  /* setup parameters */

  /* set dmem pointer to modulus */
  la       x2, modulus
  la       x3, dptr_m
  sw       x2, 0(x3)

  /* set dmem pointer to message */
  la       x2, message
  la       x3, dptr_in
  sw       x2, 0(x3)

  /* set dmem pointer to output buffer */
  la       x2, buf_out
  la       x3, dptr_out
  sw       x2, 0(x3)

  /* set dmem pointer to RR buffer */
  la       x2, buf_rr
  la       x3, dptr_rr
  sw       x2, 0(x3)

  /* set dmem pointer to m0iv buffer */
  la       x2, buf_m0inv
  la       x3, dptr_m0inv
  sw       x2, 0(x3)

  /* set number of limbs */
  la       x3, param_limbs
  li       x2, 8
  sw       x2, 0(x3)

  jal      x1, modload
  jal      x1, modexp_65537

  /* pointer to out buffer */
  la       x3, dptr_out
  lw       x21, 0(x3)

  /* copy all limbs of result to wide reg file */
  li       x8, 0
  loop     x30, 2
    bn.lid   x8, 0(x21++)
    addi     x8, x8, 1

  ecall

.data

/* modulus */
modulus:
  .word 0x241de231
  .word 0xd8928128
  .word 0x714d73bf
  .word 0x1be2197d
  .word 0x808e08a2
  .word 0x776aaeff
  .word 0x29fda181
  .word 0x31f5775a

  .word 0xdfcea14e
  .word 0xda8bc319
  .word 0x047e837b
  .word 0x7b128e07
  .word 0xd34e4f0f
  .word 0xead68451
  .word 0xa330a776
  .word 0x9f50625a

  .word 0x7bbc9d35
  .word 0xf02134be
  .word 0x3dffccbf
  .word 0xba1c4ced
  .word 0xf24d5244
  .word 0x1048e13a
  .word 0x2d38ce40
  .word 0x37e582f0

  .word 0xc68e93ed
  .word 0x5616632e
  .word 0xc19daa6c
  .word 0x4f9aed87
  .word 0xf5794737
  .word 0x9738717d
  .word 0x7145315a
  .word 0x5088166e

  .word 0x1941279c
  .word 0xba7ea801
  .word 0xd30ae3f8
  .word 0x997faf2a
  .word 0xd3781154
  .word 0xc0e39b0a
  .word 0x1282c2a2
  .word 0x919e1c49

  .word 0xed64fdcf
  .word 0xa28c83f6
  .word 0x06c441cb
  .word 0xf57ce25a
  .word 0xe362e592
  .word 0x517c76a0
  .word 0x2b8acf04
  .word 0x6cf03dc9

  .word 0xd43abdce
  .word 0x2d64e99a
  .word 0x2df0eb50
  .word 0x6e77e98d
  .word 0x36d3a721
  .word 0x0bfe5479
  .word 0xeff2e2a2
  .word 0x8cc2e493

  .word 0x8ea2a8ab
  .word 0x76bdbfc4
  .word 0x4a039a5b
  .word 0xe05a3951
  .word 0xf15e0032
  .word 0x8630939c
  .word 0x04f4306b
  .word 0x839130ab

/* message */
message:
  .word 0x03020100
  .word 0x07060504
  .word 0x0b0a0908
  .word 0x0f0e0d0c
  .word 0x13121110
  .word 0x17161514
  .word 0x1b1a1918
  .word 0x1f1e1d1c

  .word 0x23222120
  .word 0x27262524
  .word 0x2b2a2928
  .word 0x2f2e2d2c
  .word 0x33323130
  .word 0x37363534
  .word 0x3b3a3938
  .word 0x3f3e3d3c

  .word 0x43424140
  .word 0x47464544
  .word 0x4b4a4948
  .word 0x4f4e4d4c
  .word 0x53525150
  .word 0x57565554
  .word 0x5b5a5958
  .word 0x5f5e5d5c

  .word 0x63626160
  .word 0x67666564
  .word 0x6b6a6968
  .word 0x6f6e6d6c
  .word 0x73727170
  .word 0x77767574
  .word 0x7b7a7978
  .word 0x7f7e7d7c

  .word 0x83828180
  .word 0x87868584
  .word 0x8b8a8988
  .word 0x8f8e8d8c
  .word 0x93929190
  .word 0x97969594
  .word 0x9b9a9998
  .word 0x9f9e9d9c

  .word 0xa3a2a1a0
  .word 0xa7a6a5a4
  .word 0xabaaa9a8
  .word 0xafaeadac
  .word 0xb3b2b1b0
  .word 0xb7b6b5b4
  .word 0xbbbab9b8
  .word 0xbfbebdbc

  .word 0xc3c2c1c0
  .word 0xc7c6c5c4
  .word 0xcbcac9c8
  .word 0xcfcecdcc
  .word 0xd3d2d1d0
  .word 0xd7d6d5d4
  .word 0xdbdad9d8
  .word 0xdfdedddc

  .word 0xe3e2e1e0
  .word 0xe7e6e5e4
  .word 0xebeae9e8
  .word 0xefeeedec
  .word 0xf3f2f1f0
  .word 0xf7f6f5f4
  .word 0xfbfaf9f8
  .word 0x00fefdfc

/* output buffer */
buf_out:
  .zero 256

/* RR buffer */
buf_rr:
  .zero 256

/* m0inv buffer */
buf_m0inv:
  .zero 32

/* expected encrypted message in regfile:
 w0 = 0x01bebd863c7c01bc8b60cbf846ad6540a8ce2d558dc93675fd11f143c630fef5
 w1 = 0x1be3f69e372a39dbb31343d039b26012f836c739ab759ac42209752177a7da46
 w2 = 0x403c6bf9d811c3d283d5c1ebbbc9588aebb77745ec94bd75c857b0a65232af44
 w3 = 0xa2f4013df746bd6277866e33b726cfea6ef6d8072727537bc9afb7d99eb6c082
 w4 = 0x240b5f37baa743560057e1845ec9395c7803cc64615ac6404447b5602f99272e
 w5 = 0x877b0ca7ccf59decb917f7b5972e998dce4d108413d3fdaace8ab6306141feb1
 w6 = 0x8bd9bfa74e79efa10a9fca274bfaa78ac17914035a029a7555ed8c788d3302da
 w7 = 0x74f56a0904d25f5c5567b19308ca429332b7e6fc76e6b2c7a42532c1f71a2fac
*/
