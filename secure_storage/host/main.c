/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_storage_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void usage(void) {
	printf("Usage: secure_storage store -f input_file_name -i file_id\n ");
	printf("Usage: secure_storage get -f output_file_name -i file_id\n ");
	return(1);
}

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t *data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = *data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}
	*data_len = op.params[1].tmpref.size;
	return res;
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);

	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000

int main(int argc, char *argv[])
{
	char *file_name;
	char *file_id;

	if( (argc != 6) && (strcmp(argv[1], "-h") != 0) ){
		usage();
	}

	enum {STORE, GET} mode = GET;
	if (strcmp(argv[1], "store") == 0)
		mode = STORE;

	for (int i = 2; i < argc; i=i+2){
		if (strcmp(argv[i], "-f") == 0) {
			file_name = argv[i+1];
		}
		else if (strcmp(argv[i], "-i") == 0) {
			file_id = argv[i+1];
		}
		else {
			usage();
		}
	}

	// Read or write file open
	// TODO: Close files afterwards
	
	if(mode == STORE) {
		printf("Storing file to secure storage...\n");
		char *buffer = NULL;
		FILE *file_handle = NULL;
		file_handle = fopen(file_name, "rb");
		fseek(file_handle, 0L, SEEK_END); // Go to the end of the file
    	long size = ftell(file_handle); // Get file size
    	rewind(file_handle); // Go to the beginning of the file
    	buffer = malloc(size); // Allocate a buffer the size of the file
		fread(buffer, size, 1, file_handle); // Copy file contents to the buffer
		
		fclose(file_handle); file_handle = NULL; // Close and nullify the file

		struct test_ctx ctx;
		TEEC_Result res;
		prepare_tee_session(&ctx);
		res = write_secure_object(&ctx, file_id,
					buffer, size);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to create an object in the secure storage");

		printf("Stored file to secure storage.\n");
		terminate_tee_session(&ctx);
		return 0;

	} else if (mode == GET) {

		char *buffer[7000];
		FILE *file_handle = NULL;
		struct test_ctx ctx;
		TEEC_Result res;
		prepare_tee_session(&ctx);
		printf("Pulling file from secure storage...\n");
		size_t size = sizeof(buffer);
		res = read_secure_object(&ctx, file_id,
					buffer, &size);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to read an object from the secure storage");
		
		file_handle = fopen(file_name, "wb");
		fwrite(buffer, size, 1, file_handle);

		fclose(file_handle); file_handle = NULL;

		printf("Pulled file from secure storage.\n");
		terminate_tee_session(&ctx);
		return 0;
	}



	
	// res = write_secure_object(&ctx, file_id,
	// 			  buffer, sizeof(buffer));
	// if (res != TEEC_SUCCESS)
	// 	errx(1, "Failed to create an object in the secure storage");


	

	// res = delete_secure_object(&ctx, obj1_id);
	// if (res != TEEC_SUCCESS)
	// 	errx(1, "Failed to delete the object: 0x%x", res);


	
}
