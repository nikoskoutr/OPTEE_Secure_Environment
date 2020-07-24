#include <se_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

#define MAX_AES_KEYSIZE 256
#define MAX_RSA_KEYSIZE 2048

struct cryptography
{
  uint32_t algo;
  uint32_t mode;
  uint8_t *IV;
};


/*!
 * \brief RSA_Operation Wraps the RSA operations in one function.
 * \param mode          Supported mode are TEE_MODE_ENCRYPT and
 * TEE_MODE_DECRYPT.
 * \param algorithm     Supported algorithms are defined above for RSA.
 * \param key           The key that will be used for the operation.
 * \param in_data       Pointer to the input data buffer.
 * \param in_data_len   Size of the input data buffer.
 * \param out_data      Pointer for the output data buffer. For the signature
 * operation it is also used for input
 * \param out_data_len  Size of the output data buffer.
 */
static TEE_Result RSA_Operation(TEE_OperationMode mode, uint32_t algorithm, TEE_ObjectHandle key,
                                void *in_data, uint32_t in_data_len, void *out_data,
                                uint32_t *out_data_len)
{

  TEE_OperationHandle rsa_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;
  ret = TEE_AllocateOperation(&rsa_operation, algorithm, mode, MAX_RSA_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    EMSG("TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  ret = TEE_SetOperationKey(rsa_operation, key);
  if (ret != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }
  // Switch with all available RSA modes: encrypt, decrypt, sign and verify.
  switch (mode) {
  case TEE_MODE_ENCRYPT:
    ret = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len, out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricEncrypt failed: 0x%x", ret);
    }
    break;

  case TEE_MODE_DECRYPT:
    ret = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, strlen(in_data), out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricDecrypt failed: 0x%x", ret);
    }
    break;

  case TEE_MODE_SIGN:
    ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, in_data, in_data_len, out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricSignDigest failed: 0x%x", ret);
    }
    break;

  case TEE_MODE_VERIFY:
    ret = TEE_AsymmetricVerifyDigest(rsa_operation, NULL, 0, in_data, in_data_len, out_data, *out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricVerifyDigest failed: 0x%x", ret);
    }
    break;

  default:
    DMSG("Unkown RSA mode type");
  }
  TEE_FreeOperation(rsa_operation);
  return ret;
}

/*!
 * \brief AES_operation Wraps the AES operations in one function.
 * \param mode          Supported mode are TEE_MODE_ENCRYPT and
 * TEE_MODE_DECRYPT.
 * \param algorithm     Supported algorithms are defined above for AES.
 * \param key           The key that will be used for the operation.
 * \param in_data       Pointer to the input data buffer.
 * \param in_data_len   Size of the input data buffer.
 * \param out_data      Pointer for the output data buffer. For the signature
 * operation it is also used for input
 * \param out_data_len  Pointer to memory containing the size of the output data
 * buffer.
 */
static TEE_Result AES_Operation(TEE_OperationMode mode, uint32_t algorithm, TEE_ObjectHandle key,
                                void *IV, uint32_t IV_len, void *in_data, uint32_t in_data_len,
                                void *out_data, uint32_t *out_data_len)
{
  TEE_OperationHandle aes_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&aes_operation, algorithm, mode, MAX_AES_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    EMSG("TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }
  ret = TEE_SetOperationKey(aes_operation, key);
  if (ret != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }
  TEE_CipherInit(aes_operation, IV, IV_len);
  ret = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data, out_data_len);
  if (ret != TEE_SUCCESS) {
    EMSG("TEE_CipherDoFinal failed: 0x%x", ret);
  }

  TEE_FreeOperation(aes_operation);
  return ret;
}

/*!
 * \brief digest_operation Wraps the hash operations in one function.
 * \param algorithm        Supported algorithms are defined above for hash
 * functions.
 * \param in_data          Pointer to the input data buffer.
 * \param in_data_len      Size of the input data buffer.
 * \param out_data         Pointer for the output data buffer.
 * \param out_data_len     Pointer to memory containing the size of the output
 * data
 * buffer.
 */
static TEE_Result digest_operation(uint32_t algorithm, void *in_data,
                                   uint32_t in_data_len, void *out_data,
                                   uint32_t *out_data_len) {
  TEE_OperationHandle dig_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;
  ret = TEE_AllocateOperation(&dig_operation, algorithm, TEE_MODE_DIGEST, 0);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(dig_operation);
    return ret;
  }

  ret = TEE_DigestDoFinal(dig_operation, in_data, in_data_len, out_data,
                          out_data_len);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_AllocateOperation failed: 0x%x", ret);
  }

  TEE_FreeOperation(dig_operation);
  return ret;
}

/*!
 * \brief store_key  Wraps the key storage operation.
 * \param key        The key to be stored.
 * \param id 		 The id of the stored object
 */
static TEE_Result store_key(TEE_ObjectHandle key, uint32_t id) {
  TEE_ObjectHandle temp = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id), NULL, key, NULL, 0, &temp);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_CreatePersistentObject failed: 0x%x", ret);
    return ret;
  }

  TEE_CloseObject(temp);
  return ret;
}

static TEE_Result cmd_gen_key(uint32_t param_types, TEE_Param params[4] ) {
	TEE_Result res;
	TEE_ObjectHandle key;
	uint32_t key_type = params[0].value.a;
  uint32_t key_size = params[0].value.b;
  uint32_t key_id = params[1].value.a;


	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

  res = store_key(key, key_id);
  if (res != TEE_SUCCESS) {
    DMSG("Key storage operation failed");
  }

	TEE_FreeTransientObject(key);
	return TEE_SUCCESS;
}

static TEE_Result get_key(uint32_t id, TEE_ObjectHandle *key) {
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id), TEE_DATA_FLAG_ACCESS_READ, key);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_OpenPersistentObject failed: 0x%x", ret);
    return ret;
  }

  return ret;
}

TEE_Result cmd_do_crypto(uint32_t param_types, TEE_Param params[4]) {
  struct cryptography crypto = {0, 0, NULL};
  uint32_t state = params[0].value.b;

  if ((state & ENCRYPT) > 0){
    crypto.mode = TEE_MODE_ENCRYPT;
  } 
  else if((state & DECRYPT) > 0)
  {
    crypto.mode = TEE_MODE_DECRYPT;
  }
  else if((state & SIGN) > 0)
  {
    crypto.mode = TEE_MODE_SIGN;
  }
  else if((state & VERIFY) > 0)
  {
    crypto.mode = TEE_MODE_VERIFY;
  }

  if ((state & CBC_NOPAD) > 0) 
  {
    crypto.algo = TEE_ALG_AES_CBC_NOPAD;
  }
  else if((state & CTR) > 0)
  {
    crypto.algo = TEE_ALG_AES_CTR;
  }
  else if((state & ENC_RSAES) > 0)
  {
    crypto.algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
  }
  else if((state & ENC_RSA) > 0)
  {
    crypto.algo = TEE_ALG_RSA_NOPAD;
  }
  else if((state & SIGN_RSASSA) > 0)
  {
    crypto.algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
  }
  else if((state & SIGN_RSASSA_MGF) > 0)
  {
    crypto.algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
  }
  else if((state & SHA256) > 0)
  {
    crypto.algo = TEE_ALG_SHA256;
  }
  else if((state & SHA512) > 0)
  {
    crypto.algo = TEE_ALG_SHA512;
  }


  if ((state & AES) > 0)
  {
    TEE_ObjectHandle key;
    TEE_Result res = get_key(params[0].value.a, &key);
    crypto.IV = params[2].memref.buffer;
    res = AES_Operation(crypto.mode, crypto.algo, key,
                        crypto.IV, strlen(crypto.IV),
                        params[1].memref.buffer, params[1].memref.size,
                        params[2].memref.buffer, &params[2].memref.size); //* IV
    TEE_CloseObject(key);
    return res;
  } 
  else if((state & RSA) > 0)
  {
    TEE_ObjectHandle key;
    TEE_Result res = get_key(params[0].value.a, &key);
    res = RSA_Operation(crypto.mode, crypto.algo, key,
                        params[1].memref.buffer, params[1].memref.size,
                        params[2].memref.buffer, &params[2].memref.size);
    TEE_CloseObject(key);
    return res;
  }
  else if((state & DIGEST) > 0)
  {
    return digest_operation(crypto.algo,
                  params[1].memref.buffer, params[1].memref.size,
                  params[2].memref.buffer, &params[2].memref.size);
  }
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void) {
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types, TEE_Param __unused params[4],
				    void __unused **sess_ctx) {
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx) {
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) 
{
	if(cmd_id == GENERATE_KEY) {
    return cmd_gen_key(param_types, params);
  } else if (cmd_id == ENC_DEC) {
    return cmd_do_crypto(param_types, params);
  } else {
    return TEE_ERROR_BAD_PARAMETERS;
	}
}