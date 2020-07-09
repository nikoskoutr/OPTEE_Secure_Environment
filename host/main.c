/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <se_ta.h>

#include <stdint.h>
#include <stdio.h>

#define TEE_TYPE_AES 0xA0000010
#define TEE_TYPE_RSA_KEYPAIR 0xA1000030

/* TEE resources */
struct test_ctx
{
  TEEC_Context ctx;
  TEEC_Session sess;
};

void usage(void)
{
  //printf("tee_crypto keygen,crypto\n(uint32) --ID ID of the stored key\n(string) --key_type AES,RSA Type of the key used or created\n(uint32) --key_size Size of the key to be created\n(null) --encrypt Encrypt operation\n(null) --decrypt (Default) Decrypt operation\n(null) --sign Sign operation\n(null) --verify Verify operation\n(string) --mode TEE_ALG_AES_CBC_NOPAD, TEE_ALG_AES_CTR, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, TEE_ALG_RSA_NOPAD\n");
  printf("usage\n");
  return;
}

void prepare_tee_session(struct test_ctx *ctx)
{
  TEEC_UUID uuid = TA_SE_UUID;
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

void do_digest(struct test_ctx *ctx, uint32_t flags, uint8_t *in, size_t in_len, uint8_t *out, uint32_t *out_len)
{
  TEEC_Operation op;
  uint32_t origin;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                   TEEC_MEMREF_TEMP_INOUT,
                                   TEEC_MEMREF_TEMP_INOUT,
                                   TEEC_NONE);

  op.params[0].value.a = flags;

  op.params[1].tmpref.buffer = in;
  op.params[1].tmpref.size = in_len;
  op.params[2].tmpref.buffer = out;
  op.params[2].tmpref.size = *out_len;

  res = TEEC_InvokeCommand(&ctx->sess, ENC_DEC,
                           &op, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand(ENCRYPT_DECRYPT) failed 0x%x origin 0x%x",
         res, origin);
  *out_len = op.params[2].tmpref.size;
}

void do_crypto(struct test_ctx *ctx, uint32_t key_id, uint32_t flags, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
  TEEC_Operation op;
  uint32_t origin;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                   TEEC_MEMREF_TEMP_INOUT,
                                   TEEC_MEMREF_TEMP_INOUT,
                                   TEEC_NONE);

  op.params[0].value.a = key_id;
  op.params[0].value.b = flags;

  op.params[1].tmpref.buffer = in;
  op.params[1].tmpref.size = in_len;
  op.params[2].tmpref.buffer = out;
  op.params[2].tmpref.size = *out_len;

  res = TEEC_InvokeCommand(&ctx->sess, ENC_DEC,
                           &op, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand(ENCRYPT_DECRYPT) failed 0x%x origin 0x%x",
         res, origin);
  *out_len = op.params[2].tmpref.size;
}

void do_keygen(struct test_ctx *ctx, uint32_t key_type, uint32_t key_size, uint32_t key_id)
{
  TEEC_Operation op;
  uint32_t origin;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                   TEEC_VALUE_INPUT,
                                   TEEC_VALUE_INPUT,
                                   TEEC_NONE);

  op.params[0].value.a = key_type;
  op.params[0].value.b = key_size;
  op.params[1].value.a = key_id;

  res = TEEC_InvokeCommand(&ctx->sess, GENERATE_KEY, &op, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand(GENERATE_KEY) failed 0x%x origin 0x%x",
         res, origin);
}

void set_mode(char *mode, uint32_t *flags_p)
{
  if (strcmp(mode, "TEE_ALG_AES_CBC_NOPAD") == 0)
  {
    *flags_p |= CBC_NOPAD;
  }
  else if (strcmp(mode, "TEE_ALG_AES_CTR") == 0)
  {
    *flags_p |= CTR;
  }
  else if (strcmp(mode, "TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256") == 0)
  {
    *flags_p |= ENC_RSAES;
  }
  else if (strcmp(mode, "TEE_ALG_RSA_NOPAD") == 0)
  {
    *flags_p |= ENC_RSA;
  }
  else if (strcmp(mode, "TEE_ALG_RSASSA_PKCS1_V1_5_SHA256") == 0)
  {
    *flags_p |= SIGN_RSASSA;
  }
  else if (strcmp(mode, "TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256") == 0)
  {
    *flags_p |= SIGN_RSASSA_MGF;
  }
  else if (strcmp(mode, "TEE_ALG_SHA256") == 0)
  {
    *flags_p |= SHA256;
  }
  else if (strcmp(mode, "TEE_ALG_SHA512") == 0)
  {
    *flags_p |= SHA512;
  }
  else
  {
    printf("Available modes: TEE_ALG_AES_CBC_NOPAD\nTEE_ALG_AES_CTR\nTEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256\nTEE_ALG_RSA_NOPAD\nTEE_ALG_RSASSA_PKCS1_V1_5_SHA256\nTEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256\n");
  }
  return;
}

int main(int argc, char *argv[])
{
  uint8_t *IV = NULL;
  uint8_t *input = NULL;
  FILE *out_file = NULL;
  FILE *in_file = NULL;
  uint32_t key_id = 0;
  uint32_t key_size = 0;
  uint32_t key_type = 0;
  uint32_t flags = 0;
  struct test_ctx ctx = {};

  enum
  {
    KEYGEN,
    CRYPTO
  } mode = CRYPTO;
  if (strcmp(argv[1], "keygen") == 0)
  {
    mode = KEYGEN;
  }

  for (int i = 2; i < argc; i++)
  {
    if (strcmp(argv[i], "--IV") == 0)
    {
      if (strlen(argv[i + 1]) != 16)
      {
        printf("IV should be 16 bytes\n");
        return (-1);
      }
      IV = argv[i + 1];
    }
    else if (strcmp(argv[i], "--ID") == 0)
    {
      key_id = atoi(argv[i + 1]);
    }
    else if (strcmp(argv[i], "--key_type") == 0)
    {
      if (strcmp(argv[i + 1], "RSA") == 0)
      {
        key_type = TEE_TYPE_RSA_KEYPAIR;
        flags |= RSA;
      }
      else if (strcmp(argv[i + 1], "AES") == 0)
      {
        key_type = TEE_TYPE_AES;
        flags |= AES;
      }
      else
      {
        printf("Available key types: AES, RSA\n");
      }
    }
    else if (strcmp(argv[i], "--key_size") == 0)
    {
      key_size = atoi(argv[i + 1]);
    }
    else if (strcmp(argv[i], "--encrypt") == 0)
    {
      flags |= ENCRYPT;
    }
    else if (strcmp(argv[i], "--decrypt") == 0)
    {
      flags |= DECRYPT;
    }
    else if (strcmp(argv[i], "--sign") == 0)
    {
      flags |= SIGN;
    }
    else if (strcmp(argv[i], "--verify") == 0)
    {
      flags |= VERIFY;
    }
    else if(strcmp(argv[i], "--digest") == 0)
    {
      flags|= DIGEST;
    }
    else if (strcmp(argv[i], "--mode") == 0)
    {
      set_mode(argv[i + 1], &flags);
    }
    else if (strcmp(argv[i], "--in") == 0)
    {
      if (in_file == NULL)
      {
        printf("DEBUG: Entered --in\n");
        input = argv[i + 1];
      }
      else
      {
        printf("--in_file already specified\n");
      }
    }
    else if (strcmp(argv[i], "--in_file") == 0)
    {
      if (input == NULL)
      {
        in_file = fopen(argv[i + 1], "rb");
        printf("DEBUG: Entered --in_file\n");
      }
      else
      {
        printf("--in already specified\n");
      }
    }
    else if (strcmp(argv[i], "--out_file") == 0)
    {
      out_file = fopen(argv[i + 1], "wb");
    }
    else if (strcmp(argv[i], "--help") == 0)
    {
      usage();
    }
  }

  prepare_tee_session(&ctx);
  if (mode == CRYPTO)
  {
    uint8_t in[4096];
    uint8_t out[4096];
    size_t in_len;
    size_t out_len;

    out_len = 4096;

    if ( (IV != NULL) && (key_type == TEE_TYPE_AES) )
    {
      memcpy(out, IV, 17);
    }

    if (input != NULL)
    {
      memcpy(in, input, (strlen(input) + 1));
      in_len = strlen(input);
    }
    else if (in_file != NULL)
    {
      fseek(in_file, 0L, SEEK_END);
      size_t file_size = ftell(in_file);
      in_len = file_size;
      fseek(in_file, 0L, SEEK_SET);
      fread(in, file_size, 1, in_file);
      fclose(in_file);
    }

    do_crypto(&ctx, key_id, flags, in, in_len, out, &out_len);

    fwrite(out, out_len, 1, out_file);
    terminate_tee_session(&ctx);
  }
  else if (mode == KEYGEN)
  {
    do_keygen(&ctx, key_type, key_size, key_id);
    terminate_tee_session(&ctx);
  }

  return 0;
}