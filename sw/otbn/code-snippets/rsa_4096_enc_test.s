/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */


.text

/**
 * Standalone RSA 4096 encrypt
 *
 * Uses OTBN modexp bignum lib to encrypt the message from the .data segment
 * in this file with the public key consisting of e=65537 and modulus from
 * .data segment in this file.
 *
 * Copies the encrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
run_rsa_4096_enc:

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
  li       x2, 16
  sw       x2, 0(x3)

  jal      x1, modload
  jal      x1, modexp_65537

  /* copy all limbs of result to wide reg file */
  la       x3, dptr_out
  lw       x21, 0(x3)
  li       x8, 0
  loop     x30, 2
    bn.lid   x8, 0(x21++)
    addi     x8, x8, 1

  ecall

.data

/* modulus */
modulus:
  .word 0xca4cb8c5
  .word 0xacbf59ea
  .word 0xc7d19951
  .word 0xfc78772a
  .word 0x9884d359
  .word 0xc8b71d3a
  .word 0x6f7be956
  .word 0x33907bd6

  .word 0x65742dd6
  .word 0x2f311f1a
  .word 0x31591b1d
  .word 0xbce8164f
  .word 0x4d4eb163
  .word 0x6d03eace
  .word 0x06c5ce49
  .word 0x9f741209

  .word 0x0e956d21
  .word 0x9a06c226
  .word 0x6ef9eb0d
  .word 0x3875f9c9
  .word 0x7aab0b6c
  .word 0x9d6cfcdb
  .word 0x24596fac
  .word 0xeed557e1

  .word 0x2e3db5f5
  .word 0x9a80bcc4
  .word 0x1572fb18
  .word 0x019d7bf5
  .word 0x2a45a393
  .word 0x4561517c
  .word 0x8cc1aac7
  .word 0x328943a3

  .word 0x8894e18b
  .word 0x231ecfa4
  .word 0x1c7ffd25
  .word 0xb709c6d6
  .word 0x874dff25
  .word 0xf2b02b35
  .word 0x1691899c
  .word 0x29211442

  .word 0x2c49df64
  .word 0x616b0606
  .word 0x650bbbae
  .word 0x2a916b85
  .word 0xc50052b8
  .word 0xd11cf5c3
  .word 0x4a75307a
  .word 0x7a8a2117

  .word 0x2538cf39
  .word 0xf5464acb
  .word 0x8a0f87e1
  .word 0x0205bbc6
  .word 0xac9e565c
  .word 0x33e44c85
  .word 0x6dbda23a
  .word 0x3f7c6bac

  .word 0x55d5ff3a
  .word 0x78a34253
  .word 0x34dc89a0
  .word 0x09a70863
  .word 0xa1199faf
  .word 0xe3e080cc
  .word 0x32279bcf
  .word 0xdc00afe3

  .word 0xd2d134a4
  .word 0xb4875fd3
  .word 0xdfa34177
  .word 0x008e1049
  .word 0x09159889
  .word 0x876148bc
  .word 0x416eca4a
  .word 0x96cfaa3f

  .word 0x728e4dcc
  .word 0xef7755d4
  .word 0x04f9b6db
  .word 0x1f4c970a
  .word 0xf9c15c32
  .word 0x9b6fa78b
  .word 0xdd642c5a
  .word 0x5bcd59bb

  .word 0xb2783504
  .word 0x35ea77c9
  .word 0xf8437545
  .word 0x4e3a8b36
  .word 0xa12b5d07
  .word 0x9353b3b6
  .word 0x18edb2fa
  .word 0xb1d543a8

  .word 0xc83dc05b
  .word 0x1709afe2
  .word 0x5c6232c2
  .word 0x98d706bb
  .word 0x780fd045
  .word 0x628a900e
  .word 0x5fc3ccb3
  .word 0x6d1d12b5

  .word 0xfe2a0bea
  .word 0x7218b172
  .word 0x989a6b0d
  .word 0x930d746e
  .word 0x1edfa667
  .word 0x7046ce39
  .word 0xad77304e
  .word 0x47bcecba

  .word 0xad159f6b
  .word 0x5f3a0a2b
  .word 0x7b2c41a4
  .word 0xd8e8959a
  .word 0xde870df3
  .word 0x3dfea559
  .word 0x12f03cc9
  .word 0x0b5c1cb6

  .word 0x8ac26f90
  .word 0x5958973b
  .word 0xee6004b0
  .word 0xc202c4ae
  .word 0x66a8600b
  .word 0xebf9eeb0
  .word 0x1f250fed
  .word 0xb89cd674

  .word 0xbd9650ba
  .word 0xae33f7e4
  .word 0x6594b6c7
  .word 0x81d8e523
  .word 0xc79fd3ff
  .word 0xdf9f6598
  .word 0x9b04652d
  .word 0xbdc2e5c1

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
  .word 0xfffefdfc

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
  .zero 512

/* RR buffer */
buf_rr:
  .zero 512

/* m0inv buffer */
buf_m0inv:
  .zero 32

/* expected encrypted message in regfile:
 w0 = 0xb7a599f4c37e0748f732712917f791e0f5e60d1d99d51b43129e49191c2c14e6
 w1 = 0x706018880f4b04bbd2e65f986e8451f9fe73570f3dc9c9c5173ff93712e10017
 w2 = 0xddad82324225856e38c232f89fcae9dc3b52af761bb37464deb9c371b8ef2faf
 w3 = 0x25a7b6b15ec1085b33270cbb5bd312c4561c5d17a2e9af1e5c81147e9715db3a
 w4 = 0x7750273d87f98319ea82c26833144273b4451981e216ed4ab8dfc06be8680647
 w5 = 0x6379de3c9c39a166030db3498d0618c62e91d103e227c975d1f915bdb41f575c
 w6 = 0x08c16b0d1fc358f7db81fa201bee6f13ef267cf2f084764784a17e8cff57545b
 w7 = 0xce79da5e3df1358e05e9a561fc0bd4012ad5c0bfa96564124174bab9f37c3e69
 w8 = 0x22ce2950d59779a590797b96425a2cdaf0902f0b299dfdbcbcc9a2e73f97b37c
 w9 = 0xf5614046a8350bc7c2a345a1a9cbf433b9919af3f4294c86a248174b52d36f31
w10 = 0xbda2de13424a8990a374b9349ee1c70720dc5746eec168f5e47256e564d49e47
w11 = 0xb7f3f3f5a948496e2362e2bc54f09589eaa0d5d53513a5d1592ed4823953b5f5
w12 = 0x13f358c7a3152634052748eaae253318c3163d019eae154ceebc44ec6da3efa3
w13 = 0xbcc1d63a271918b66b038b6440c16a8b4262fe2cdfcf32bef78d74b2d6ec919a
w14 = 0xffd19f7c737081617e5f2b7af307df21ce05d268120ef6183460265a1f977388
w15 = 0x2390bb53f64c4f3ed2e71e95bd1f1773f9b8c46094c56feeb4f8ee0ed40c4158
*/
