/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */


.text

/**
 * Standalone RSA 2048 decrypt
 *
 * Uses OTBN modexp bignum lib to decrypt the message from the .data segment
 * in this file with the private key contained in .data segment of this file.
 *
 * Copies the decrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
 run_rsa_2048_dec:

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
  li       x2, 8
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

/* encrypted message */
ciphertext:
  .word 0xc630fef5
  .word 0xfd11f143
  .word 0x8dc93675
  .word 0xa8ce2d55
  .word 0x46ad6540
  .word 0x8b60cbf8
  .word 0x3c7c01bc
  .word 0x01bebd86

  .word 0x77a7da46
  .word 0x22097521
  .word 0xab759ac4
  .word 0xf836c739
  .word 0x39b26012
  .word 0xb31343d0
  .word 0x372a39db
  .word 0x1be3f69e

  .word 0x5232af44
  .word 0xc857b0a6
  .word 0xec94bd75
  .word 0xebb77745
  .word 0xbbc9588a
  .word 0x83d5c1eb
  .word 0xd811c3d2
  .word 0x403c6bf9

  .word 0x9eb6c082
  .word 0xc9afb7d9
  .word 0x2727537b
  .word 0x6ef6d807
  .word 0xb726cfea
  .word 0x77866e33
  .word 0xf746bd62
  .word 0xa2f4013d

  .word 0x2f99272e
  .word 0x4447b560
  .word 0x615ac640
  .word 0x7803cc64
  .word 0x5ec9395c
  .word 0x0057e184
  .word 0xbaa74356
  .word 0x240b5f37

  .word 0x6141feb1
  .word 0xce8ab630
  .word 0x13d3fdaa
  .word 0xce4d1084
  .word 0x972e998d
  .word 0xb917f7b5
  .word 0xccf59dec
  .word 0x877b0ca7

  .word 0x8d3302da
  .word 0x55ed8c78
  .word 0x5a029a75
  .word 0xc1791403
  .word 0x4bfaa78a
  .word 0x0a9fca27
  .word 0x4e79efa1
  .word 0x8bd9bfa7

  .word 0xf71a2fac
  .word 0xa42532c1
  .word 0x76e6b2c7
  .word 0x32b7e6fc
  .word 0x08ca4293
  .word 0x5567b193
  .word 0x04d25f5c
  .word 0x74f56a09

/* private exponent */
priv_exp:
  .word 0x2590fc0d
  .word 0x6142365e
  .word 0xdf11ab84
  .word 0x66084a37
  .word 0x9fe3da86
  .word 0xafada26c
  .word 0x70f64a2a
  .word 0xbfc9180c

  .word 0x7bc6c75a
  .word 0x1e62ce1c
  .word 0x585d9125
  .word 0x9537d870
  .word 0x6e9fbdbf
  .word 0xfc09b908
  .word 0x34ee75a0
  .word 0x69cad90d

  .word 0x72b35ef1
  .word 0x06a6f07c
  .word 0x76f2b1af
  .word 0x7d81daf0
  .word 0x2bfca9ed
  .word 0x19af3e50
  .word 0x7b383970
  .word 0xc108efb5

  .word 0x5c0442af
  .word 0x84ebb98f
  .word 0xda6bb8ed
  .word 0x31615ffd
  .word 0x3dac0df1
  .word 0x65152320
  .word 0x54235c8c
  .word 0x2095e0c5

  .word 0xf0adfdc7
  .word 0xe57bfb35
  .word 0xd46688b8
  .word 0xae2a7ddd
  .word 0x894b0001
  .word 0x53b847ea
  .word 0x37b55699
  .word 0xb97eea71

  .word 0x1b63d158
  .word 0x84db8a9a
  .word 0x4ab074e7
  .word 0x0f926396
  .word 0x886720fa
  .word 0xd59464ca
  .word 0x9b4c9f60
  .word 0x967245f0

  .word 0x725e9a1a
  .word 0xc9ff875c
  .word 0x42353b87
  .word 0x65abfca5
  .word 0x92d1e8b4
  .word 0xc13fb6b7
  .word 0x8b3aa00a
  .word 0xe94502e0

  .word 0xb4bb0111
  .word 0x77868ed0
  .word 0x073e845b
  .word 0x0e6d75cb
  .word 0xf48fe63e
  .word 0x32c4e607
  .word 0xfcbb5bdc
  .word 0x04a062d4

/* output buffer */
buf_out:
  .zero 256

/* RR buffer */
buf_rr:
  .zero 256

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
 w7 = 0x00fefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
*/
