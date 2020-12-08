/* Copyright lowRISC Contributors.
 * Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE.dcrypto file.
 */


.text

/**
 * Standalone RSA 1024 decrypt
 *
 * Uses OTBN modexp bignum lib to decrypt the message from the .data segment
 * in this file with the private key contained in .data segment of this file.
 *
 * Copies the decrypted message to wide registers for comparison (starting at
 * w0). See comment at the end of the file for expected values.
 */
 run_rsa_1024_enc:
  jal      x1, modload
  jal      x1, modexp
  /* pointer to out buffer */
  lw        x21, 116(x0)

  /* copy all limbs of result to wide reg file */
  li       x8, 0
  loop     x30, 2
    bn.lid   x8, 0(x21++)
    addi     x8, x8, 1

  ecall


.data

/* descriptor 1: a=in, b=RR, c=in
   convert to Montgomery */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000004c0
.word 0x000002c0
.word 0x000004c0
.word 0x0000000c
.word 0x0000000b

/* descriptor 2: a=out, b=out, c=out
   square */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000008e0
.word 0x000008e0
.word 0x000008e0
.word 0x0000000c
.word 0x0000000b

/* descriptor 3: a=in, b=out, c=out
   multiply */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000004c0
.word 0x000008e0
.word 0x000008e0
.word 0x0000000c
.word 0x0000000b

/* descriptor 4: a=in, b=exp, c=out
   shift exponent and convert back */
.word 0x00000080
.word 0x00000280
.word 0x000002c0
.word 0x000008e0
.word 0x000006c0
.word 0x000008e0
.word 0x0000000c
.word 0x0000000b


/* modulus */
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


/* encrypted message */
/* skip to 1216 */
.skip 704

.word 0xcb395c69
.word 0xc893f7fa
.word 0x84801cd9
.word 0x3f58ab47
.word 0xc02a842c
.word 0x39f320e1
.word 0xa88b5607
.word 0x208c88ce

.word 0x45651ec3
.word 0x0c0c2342
.word 0x9fd76ced
.word 0x7507da80
.word 0xe9d1244a
.word 0xe43bc64b
.word 0xbde34093
.word 0x002e3c3a

.word 0x489938f6
.word 0x6a8bdfea
.word 0x157f5c32
.word 0x38beea41
.word 0xc2995bef
.word 0x0c75bc2f
.word 0x894b3089
.word 0xd4b9a326

.word 0xd15a00e0
.word 0xa21dbbd4
.word 0xa64feb8f
.word 0xc282e731
.word 0x9dc63e4b
.word 0xc157612b
.word 0x29df94bb
.word 0x25d55e3a

.word 0xe84f6e3f
.word 0x5e14e740
.word 0xb719810f
.word 0xbb85d7c6
.word 0x99a800ad
.word 0xa815e7ea
.word 0x13874cba
.word 0xdc8b48a0

.word 0xeb9a9f87
.word 0xe906823a
.word 0xea963ba8
.word 0x0fdd3b14
.word 0x70788749
.word 0xe9c62302
.word 0x5dc05ded
.word 0xe43373b8

.word 0xac93b3ec
.word 0x59469bf5
.word 0x3b2e17a6
.word 0x106d8be8
.word 0x4af69298
.word 0x2b42a841
.word 0xbce87f5a
.word 0x959e7c98

.word 0x66f8b8fd
.word 0x63d35cb0
.word 0xb0ebc2bb
.word 0xae80bbd5
.word 0x5af18f06
.word 0xc410427d
.word 0xa12a9916
.word 0x548708e0

.word 0x99fa3278
.word 0xd58200d4
.word 0xaee6e233
.word 0x4d03e03a
.word 0x8e57d861
.word 0x4e02a082
.word 0x68f11d8f
.word 0xee88e98a

.word 0xa0ca9612
.word 0xc25a7350
.word 0x23abe994
.word 0xea311f10
.word 0x213272cc
.word 0xf4ba26bf
.word 0x2564220d
.word 0xc7c6c945

.word 0xbaa93962
.word 0x3cd3d9b4
.word 0xf352925f
.word 0x2b97fbe9
.word 0x850b09f1
.word 0xf8f0e20c
.word 0x7827d183
.word 0x10e1bb54

.word 0x739182f7
.word 0xf9636e77
.word 0xe7cdb720
.word 0x620b34cc
.word 0xe9f4a489
.word 0x141b17c4
.word 0x8f441255
.word 0x0efc1d9a


/* private exponent */
/* skip to 1728 */
.skip 128

.word 0x2c8b61d5
.word 0x7b626da4
.word 0xf4d352ad
.word 0x186b0072
.word 0x58fd6739
.word 0x36a32147
.word 0xb840ef2c
.word 0x7520f3b0

.word 0x17a34ff9
.word 0x0f7625f7
.word 0xdbadcc39
.word 0x44c6892e
.word 0x3bd344c1
.word 0x0a61209c
.word 0xc2c3df5b
.word 0x4bddd7e7

.word 0xabd6c1eb
.word 0x52d4477d
.word 0xd001af35
.word 0xd7f04645
.word 0x92ce1441
.word 0x8d086a4e
.word 0x1ffc3341
.word 0xf0386f47

.word 0xa10ca5b3
.word 0x0b077a0d
.word 0x79c26564
.word 0xb53549aa
.word 0x4e30dcfb
.word 0xc38274a2
.word 0xb16f30a8
.word 0x6d7fd209

.word 0xdf6fa798
.word 0x6f61f256
.word 0x61f68b18
.word 0x09f5e0a7
.word 0xdcd268b1
.word 0x2bab0774
.word 0x0e4f9e18
.word 0x27cec3fe

.word 0xe4f337eb
.word 0xd0d2136c
.word 0xd06f5f68
.word 0x5ed2dc61
.word 0x8a56ff77
.word 0xc85bd725
.word 0x238aaaa9
.word 0x6f540444

.word 0x60a18586
.word 0xa6f9abf3
.word 0xa1e9e16d
.word 0x660dd9fd
.word 0x94f3adeb
.word 0xd0298a6a
.word 0xd885870b
.word 0xdd80299c

.word 0x948ca75d
.word 0xfff126d5
.word 0xa388a552
.word 0xd2406d3a
.word 0xef8528ca
.word 0xfa10e4cd
.word 0xcba6bd2d
.word 0x1402292f

.word 0xde96827a
.word 0x215c5d64
.word 0x050ac3eb
.word 0x4f1b57de
.word 0x64bc3c6b
.word 0xa81d5d51
.word 0x713cc70a
.word 0x7ece0c2b

.word 0x116c1582
.word 0x79b6f1ee
.word 0xb0e13bc4
.word 0x5e32e33b
.word 0x72e297b4
.word 0x3e3ac227
.word 0x0e1d2937
.word 0x370153e4

.word 0x0734ede4
.word 0xbbea6e59
.word 0xf328fb78
.word 0x958f69a1
.word 0xb802cbc8
.word 0xf04ba00e
.word 0xaea66246
.word 0x53962ea7

.word 0xd150e023
.word 0x564f388b
.word 0x041798f2
.word 0x86ab24bb
.word 0x48478a84
.word 0x2e103c94
.word 0x653dd70d
.word 0x04616b87


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
w11 = 0x007e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463626160
*/
