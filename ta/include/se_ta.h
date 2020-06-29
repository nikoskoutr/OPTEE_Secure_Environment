/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __SE_TA_H__
#define __SE_TA_H__

/*
 * This TA implements HOTP according to:
 * https://www.ietf.org/rfc/rfc4226.txt
 */
/* TODO: Change the UUID - propagate to Makefile */
#define TA_SE_UUID \
	{ 0x484d4143, 0x2d53, 0x4841, \
		{ 0x31, 0x20, 0x4a, 0x6f, 0x63, 0x6b, 0x65, 0x42 } }

/* TODO: Change The function ID(s) implemented in this TA */
#define TA_HOTP_CMD_REGISTER_SHARED_KEY	0
#define TA_HOTP_CMD_GET_HOTP		1

#endif

#define AES_RSA  1   /* 0000 0001 */
#define ENCRYPT_DECRYPT  2   /* 0000 0010 */
#define SIGN_VERIFY  4   /* 0000 0100 */
#define AES_CBC_CTR  8   /* 0000 1000 */ /* TEE_ALG_AES_CBC_NOPAD TEE_ALG_AES_CTR */
#define RSA_SIGN  16  /* 0001 0000 */ /* TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 */
#define RSA_ENC  32  /* 0010 0000 */ /* TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 TEE_ALG_RSA_NOPAD */
#define FLAG_7  64  /* 0100 0000 */
#define FLAG_8  128 /* 1000 0000 */