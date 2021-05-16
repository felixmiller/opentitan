/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */


.text

/**
 * Standalone RSA 4096 decrypt
 *
 * Uses OTBN modexp bignum lib to decrypt the message from the .data segment
 * in this file with the private key contained in .data segment of this file.
 *
 * Copies the decrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
 run_rsa_4096_dec:

  /* setup parameters */

  /* set dmem pointer to modulus */
  la       x2, modulus
  la       x3, dptr_m
  sw       x2, 0(x3)

  /* set dmem pointer to ciphertext */
  la       x2, ciphertext
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

  /* set dmem pointer to private exponent */
  la       x2, priv_exp
  la       x3, dptr_exp
  sw       x2, 0(x3)

  /* set number of limbs */
  la       x3, param_limbs
  li       x2, 16
  sw       x2, 0(x3)

  jal      x1, modload
  jal      x1, modexp

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


/* encrypted message */
ciphertext:
  .word 0x1c2c14e6
  .word 0x129e4919
  .word 0x99d51b43
  .word 0xf5e60d1d
  .word 0x17f791e0
  .word 0xf7327129
  .word 0xc37e0748
  .word 0xb7a599f4

  .word 0x12e10017
  .word 0x173ff937
  .word 0x3dc9c9c5
  .word 0xfe73570f
  .word 0x6e8451f9
  .word 0xd2e65f98
  .word 0x0f4b04bb
  .word 0x70601888

  .word 0xb8ef2faf
  .word 0xdeb9c371
  .word 0x1bb37464
  .word 0x3b52af76
  .word 0x9fcae9dc
  .word 0x38c232f8
  .word 0x4225856e
  .word 0xddad8232

  .word 0x9715db3a
  .word 0x5c81147e
  .word 0xa2e9af1e
  .word 0x561c5d17
  .word 0x5bd312c4
  .word 0x33270cbb
  .word 0x5ec1085b
  .word 0x25a7b6b1

  .word 0xe8680647
  .word 0xb8dfc06b
  .word 0xe216ed4a
  .word 0xb4451981
  .word 0x33144273
  .word 0xea82c268
  .word 0x87f98319
  .word 0x7750273d

  .word 0xb41f575c
  .word 0xd1f915bd
  .word 0xe227c975
  .word 0x2e91d103
  .word 0x8d0618c6
  .word 0x030db349
  .word 0x9c39a166
  .word 0x6379de3c

  .word 0xff57545b
  .word 0x84a17e8c
  .word 0xf0847647
  .word 0xef267cf2
  .word 0x1bee6f13
  .word 0xdb81fa20
  .word 0x1fc358f7
  .word 0x08c16b0d

  .word 0xf37c3e69
  .word 0x4174bab9
  .word 0xa9656412
  .word 0x2ad5c0bf
  .word 0xfc0bd401
  .word 0x05e9a561
  .word 0x3df1358e
  .word 0xce79da5e

  .word 0x3f97b37c
  .word 0xbcc9a2e7
  .word 0x299dfdbc
  .word 0xf0902f0b
  .word 0x425a2cda
  .word 0x90797b96
  .word 0xd59779a5
  .word 0x22ce2950

  .word 0x52d36f31
  .word 0xa248174b
  .word 0xf4294c86
  .word 0xb9919af3
  .word 0xa9cbf433
  .word 0xc2a345a1
  .word 0xa8350bc7
  .word 0xf5614046

  .word 0x64d49e47
  .word 0xe47256e5
  .word 0xeec168f5
  .word 0x20dc5746
  .word 0x9ee1c707
  .word 0xa374b934
  .word 0x424a8990
  .word 0xbda2de13

  .word 0x3953b5f5
  .word 0x592ed482
  .word 0x3513a5d1
  .word 0xeaa0d5d5
  .word 0x54f09589
  .word 0x2362e2bc
  .word 0xa948496e
  .word 0xb7f3f3f5

  .word 0x6da3efa3
  .word 0xeebc44ec
  .word 0x9eae154c
  .word 0xc3163d01
  .word 0xae253318
  .word 0x052748ea
  .word 0xa3152634
  .word 0x13f358c7

  .word 0xd6ec919a
  .word 0xf78d74b2
  .word 0xdfcf32be
  .word 0x4262fe2c
  .word 0x40c16a8b
  .word 0x6b038b64
  .word 0x271918b6
  .word 0xbcc1d63a

  .word 0x1f977388
  .word 0x3460265a
  .word 0x120ef618
  .word 0xce05d268
  .word 0xf307df21
  .word 0x7e5f2b7a
  .word 0x73708161
  .word 0xffd19f7c

  .word 0xd40c4158
  .word 0xb4f8ee0e
  .word 0x94c56fee
  .word 0xf9b8c460
  .word 0xbd1f1773
  .word 0xd2e71e95
  .word 0xf64c4f3e
  .word 0x2390bb53

/* private exponent */
priv_exp:
  .word 0xb763ffd9
  .word 0xfc8e9748
  .word 0xb9637d59
  .word 0xc574577e
  .word 0x69b06e3e
  .word 0x5c1391e5
  .word 0xd5db305d
  .word 0xb71ca3f3

  .word 0xbd49074e
  .word 0x7a564714
  .word 0xbe97a26d
  .word 0xf024d376
  .word 0x3ad037ab
  .word 0x2547357d
  .word 0x32abb29b
  .word 0x2c0b587a

  .word 0x4d534a7c
  .word 0xcbb0a8a5
  .word 0xffd0a18e
  .word 0xa3bb4a77
  .word 0x8654440e
  .word 0x2ab3a148
  .word 0x643bc24a
  .word 0xc4d72249

  .word 0x1e8b077a
  .word 0x818270db
  .word 0x77dd2092
  .word 0x97b0b2ad
  .word 0xd7903be2
  .word 0xa1023bc5
  .word 0x325e94f0
  .word 0x3a251792

  .word 0xc9241e60
  .word 0xe28d9af4
  .word 0x62aafada
  .word 0x38912abc
  .word 0x070bed43
  .word 0x4e6b3193
  .word 0x7f165b42
  .word 0x133c79de

  .word 0xa5b9a669
  .word 0xe4779113
  .word 0x635bf7f6
  .word 0x3edec347
  .word 0xbd08910d
  .word 0xdd9f8a37
  .word 0x45e6c99e
  .word 0x0d9d4344

  .word 0xc73f83c7
  .word 0xd53d9e55
  .word 0xd58d049d
  .word 0xb7a710b7
  .word 0xa009215a
  .word 0x3acd6bd8
  .word 0xd3881c8b
  .word 0x6039d718

  .word 0xd893503b
  .word 0x1659e868
  .word 0x1f26f657
  .word 0x83280b7a
  .word 0x14118e51
  .word 0x2081307a
  .word 0x3ab0931b
  .word 0xaf19e679

  .word 0xd99880d7
  .word 0xbe0c0ad3
  .word 0x904f177f
  .word 0x7cc59a3a
  .word 0x648b33d5
  .word 0x600e329a
  .word 0x880916d1
  .word 0xedc9edf5

  .word 0x6bdceb02
  .word 0xbc590cce
  .word 0x22a8c307
  .word 0xa0aeaac6
  .word 0x2b5b331b
  .word 0x5b592f20
  .word 0x767b675d
  .word 0xcb5e9077

  .word 0xa381e147
  .word 0x36168a01
  .word 0xa642fab1
  .word 0x001190b7
  .word 0xffb45949
  .word 0x90055e4a
  .word 0x11c5b42e
  .word 0x485d8dc5

  .word 0xc2d3433f
  .word 0xaaeeb6ea
  .word 0x168cc8b7
  .word 0x8a34c596
  .word 0x9dd21b4a
  .word 0x220f566e
  .word 0x275f0e9c
  .word 0x92d7991f

  .word 0x138c324c
  .word 0xf24d21c5
  .word 0x6a066589
  .word 0x0ed80f50
  .word 0x398c7d49
  .word 0x21fa45a3
  .word 0x40e49fa7
  .word 0x7674e5ee

  .word 0x35be2292
  .word 0xf712bde5
  .word 0x7279b322
  .word 0x51ab5208
  .word 0xc7ed2f4d
  .word 0x007d4cd1
  .word 0x15ff6deb
  .word 0x61068463

  .word 0xf4722541
  .word 0x2c4f96e0
  .word 0xc63d3c8e
  .word 0x62c34136
  .word 0xcf77df01
  .word 0x44d464b5
  .word 0xc8c1a122
  .word 0x4f3c0ca6

  .word 0x9138a81b
  .word 0x68daeac5
  .word 0xd2e494a0
  .word 0xb936c774
  .word 0x3dbdc89c
  .word 0x69d9b779
  .word 0x72cebd9e
  .word 0x19d53135

/* output buffer */
buf_out:
  .zero 512

/* RR buffer */
buf_rr:
  .zero 512

/* m0inv buffer */
buf_m0inv:
  .zero 32

/* expected decrypted message in regfile:
 w0 = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
 w1 = 0x3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120
 w2 = 0x5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140
 w3 = 0x7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160
 w4 = 0x9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180
 w5 = 0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0
 w6 = 0xdfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0
 w7 = 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
 w8 = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
 w9 = 0x3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120
w10 = 0x5f5e5d5c5b5a595857565554535251504f4e4d4c4b4a49484746454443424140
w11 = 0x7f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160
w12 = 0x9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180
w13 = 0xbfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0
w14 = 0xdfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0
w15 = 0x00fefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
*/
