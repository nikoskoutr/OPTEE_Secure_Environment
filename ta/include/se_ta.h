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
	{ 0x484d4141, 0x2d53, 0x4841, \
		{ 0x31, 0x20, 0x4a, 0x6f, 0x63, 0x6b, 0x65, 0x42 } }

/* TODO: Change The function ID(s) implemented in this TA */
#define GENERATE_KEY	0
#define ENC_DEC		1

#endif

#define AES  			1	  //* AES
#define RSA  			2	  //* RSA
#define ENCRYPT			4	  //* Encrypt mode
#define DECRYPT			8	  //* Decrypt mode
#define SIGN   			16    //* Sign mode
#define VERIFY   		32    //* Verify mode
#define CBC_NOPAD 		64    //* TEE_ALG_AES_CBC_NOPAD
#define CTR  			128	  //* TEE_ALG_AES_CTR
#define ENC_RSAES 		256   //* TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256
#define ENC_RSA 		512   //* TEE_ALG_RSA_NOPAD
#define SIGN_RSASSA		1024  //* TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
#define SIGN_RSASSA_MGF	2048  //* TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256
#define SHA256          4096  //* TEE_ALG_SHA256
#define SHA512          8192  //* TEE_ALG_SHA512
#define DIGEST          16384 //* Digest mode