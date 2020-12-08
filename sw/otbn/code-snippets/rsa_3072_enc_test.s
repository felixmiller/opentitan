/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */


.text

/**
 * Standalone RSA 3072 encrypt
 *
 * Uses OTBN modexp bignum lib to encrypt the message from the .data segment
 * in this file with the public key consisting of e=65537 and modulus from
 * .data segment in this file.
 *
 * Copies the encrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
run_rsa_1024_enc:
  jal      x1, modload
  jal      x1, modexp_65537
  /* pointer to out buffer */
  lw        x21, 116(x0)

  /* copy all limbs of result to wide reg file */
  li       x8, 0
  loop     x30, 2
    bn.lid   x8, 0(x21++)
    addi     x8, x8, 1

  ecall


.data

/* reserved */
.word 0x00000000

/* number of limbs (N) */
.word 0x0000000C

/* pointer to m0' (dptr_m0d) */
.word 0x00000280

/* pointer to RR (dptr_rr) */
.word 0x000002c0

/* load pointer to modulus (dptr_m) */
.word 0x00000080

/* pointer to base bignum buffer (dptr_in) */
.word 0x000004c0

/* pointer to exponent buffer (dptr_exp, unused for encrypt) */
.word 0x000006c0

/* pointer to out buffer (dptr_out) */
.word 0x000008c0


/* Modulus */
/* skip to 128 */
.skip 96

.word 0x866cf4eb
.word 0xa30bb42d
.word 0xc26d6bd3
.word 0x196575c3
.word 0xced20f15
.word 0xb70a4e00
.word 0x39bc74b6
.word 0xb992dfbe

.word 0x1aed0695
.word 0xa4acf9a0
.word 0x82cbbb6c
.word 0xcc92828b
.word 0xda32f533
.word 0x574079e9
.word 0xdf9e1085
.word 0xa91fc6cb

.word 0xf853b7b8
.word 0x499cbb1e
.word 0xae647c2a
.word 0x0a4d3c59
.word 0x7be59f14
.word 0x10a0f014
.word 0x84dea265
.word 0x296a5d43

.word 0x0fd260f0
.word 0xb7c9a922
.word 0x1da191b3
.word 0xf63bcdf3
.word 0x8f9169d2
.word 0x1f8deb9c
.word 0x910c7443
.word 0xf57a5e1e

.word 0xdc9bc3be
.word 0x40651e5e
.word 0x4965dba3
.word 0xa61f8b6c
.word 0xf868c00e
.word 0xc4aa6d28
.word 0x5603401e
.word 0x239784bf

.word 0x5a9f5429
.word 0xd402390b
.word 0xdad4cad5
.word 0x238121f2
.word 0xb1066e7c
.word 0x289e175c
.word 0xccafd1b6
.word 0xe20c17e9

.word 0xdc01b32f
.word 0xd3acf197
.word 0x8684fa2b
.word 0xf15f20e6
.word 0xfa715fa1
.word 0x38feb663
.word 0x26fa6555
.word 0x8b6041bf

.word 0x73830cbf
.word 0x3519de8f
.word 0xf093caee
.word 0x225369ad
.word 0xe9e5f925
.word 0x81dad2ef
.word 0xab174cc8
.word 0x14b0a5af

.word 0x55db1744
.word 0x99e28f1c
.word 0xb7df21b7
.word 0x3f4f41af
.word 0x34a89217
.word 0x66446213
.word 0xb546825a
.word 0x0777b0db

.word 0xe8e84eac
.word 0x1a3aa9ed
.word 0x03f1e816
.word 0x5fefe612
.word 0xedc435d5
.word 0x8a80d905
.word 0xfd9f79ba
.word 0x1376c2ca

.word 0x45f6fbe5
.word 0xac8ec153
.word 0x5ab52ee5
.word 0xdb9c5c20
.word 0xe6058146
.word 0xcd842135
.word 0x30a4e729
.word 0x69f3820b

.word 0xe1f0ebae
.word 0xbd69deae
.word 0x0ce19c1f
.word 0x7c9cd177
.word 0x04bff960
.word 0x00235eb2
.word 0x0a66b466
.word 0x9cd2d418



/* Message */
/* skip to 1216 */
.skip 704

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
.word 0x007e7d7c


/* expected encrypted message in regfile:
 w0 = 0x208c88cea88b560739f320e1c02a842c3f58ab4784801cd9c893f7facb395c69
 w1 = 0x002e3c3abde34093e43bc64be9d1244a7507da809fd76ced0c0c234245651ec3
 w2 = 0xd4b9a326894b30890c75bc2fc2995bef38beea41157f5c326a8bdfea489938f6
 w3 = 0x25d55e3a29df94bbc157612b9dc63e4bc282e731a64feb8fa21dbbd4d15a00e0
 w4 = 0xdc8b48a013874cbaa815e7ea99a800adbb85d7c6b719810f5e14e740e84f6e3f
 w5 = 0xe43373b85dc05dede9c62302707887490fdd3b14ea963ba8e906823aeb9a9f87
 w6 = 0x959e7c98bce87f5a2b42a8414af69298106d8be83b2e17a659469bf5ac93b3ec
 w7 = 0x548708e0a12a9916c410427d5af18f06ae80bbd5b0ebc2bb63d35cb066f8b8fd
 w8 = 0xee88e98a68f11d8f4e02a0828e57d8614d03e03aaee6e233d58200d499fa3278
 w9 = 0xc7c6c9452564220df4ba26bf213272ccea311f1023abe994c25a7350a0ca9612
w10 = 0x10e1bb547827d183f8f0e20c850b09f12b97fbe9f352925f3cd3d9b4baa93962
w11 = 0x0efc1d9a8f441255141b17c4e9f4a489620b34cce7cdb720f9636e77739182f7
*/
