#include <se_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>


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
                                uint32_t out_data_len) {

  TEE_OperationHandle rsa_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&rsa_operation, algorithm, mode, MAX_RSA_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  ret = TEE_SetOperationKey(rsa_operation, key);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(rsa_operation);
    return ret;
  }

  // Switch with all available RSA modes: encrypt, decrypt, sign and verify.
  switch (mode) {
  case TEE_MODE_ENCRYPT:
    ret = TEE_AsymmetricEncrypt(rsa_operation, NULL, 0, in_data, in_data_len, out_data, &out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricEncrypt failed: 0x%x", ret);
    }
    break;
	
  case TEE_MODE_DECRYPT:
    ret = TEE_AsymmetricDecrypt(rsa_operation, NULL, 0, in_data, in_data_len, out_data, &out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricDecrypt failed: 0x%x", ret);
    }
    break;
	
  case TEE_MODE_SIGN:
    ret = TEE_AsymmetricSignDigest(rsa_operation, NULL, 0, in_data, in_data_len, out_data, &out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricSignDigest failed: 0x%x", ret);
    }
    break;

  case TEE_MODE_VERIFY:
    ret = TEE_AsymmetricVerifyDigest(rsa_operation, NULL, 0, in_data, in_data_len, out_data, out_data_len);
    if (ret != TEE_SUCCESS) {
      DMSG("TEE_AsymmetricVerifyDigest failed: 0x%x", ret);
    }
    break;

  default:
    DMSG("Unkown RSA mode type");
  }
  // Always free the operation.
  TEE_FreeOperation(rsa_operation);
  // Return the result.
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
static TEE_Result AES_operation(TEE_OperationMode mode, uint32_t algorithm, TEE_ObjectHandle key, 
                                void *IV, uint32_t IV_len, void *in_data, uint32_t in_data_len, 
                                void *out_data, uint32_t *out_data_len) {
  TEE_OperationHandle aes_operation = NULL;
  TEE_Result ret = TEE_SUCCESS;

  ret = TEE_AllocateOperation(&aes_operation, algorithm, mode, MAX_AES_KEYSIZE);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_AllocateOperation failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  ret = TEE_SetOperationKey(aes_operation, key);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_SetOperationKey failed: 0x%x", ret);
    TEE_FreeOperation(aes_operation);
    return ret;
  }

  TEE_CipherInit(aes_operation, IV, IV_len);
  ret = TEE_CipherDoFinal(aes_operation, in_data, in_data_len, out_data, out_data_len);
  if (ret != TEE_SUCCESS) {
    DMSG("TEE_CipherDoFinal failed: 0x%x", ret);
  }

  TEE_FreeOperation(aes_operation);
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
    *id_found = -1;
    return ret;
  }

  TEE_CloseObject(temp);
  return ret;
}

static TEE_Result cmd_gen_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS] ) {
	TEE_Result res;
	TEE_ObjectHandle key;
	uint32_t key_type = params[0].value.a;
  uint32_t key_size = params[0].value.b;
  uint32_t key_id = params[1].value.a;

  const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_IN, //* a: key type, b: key size
						TEE_PARAM_TYPE_VALUE_IN, //* a: key id
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

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

  ret = store_key(key, key_id);
  if (ret != TEE_SUCCESS) {
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

TEE_Result cmd_do_crypto(uint32_t param_types, TEE_Param params[4], TEE_ObjectHandle key) {
  // TODO
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

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
	switch (cmd_id) {
	case GENERATE_KEY:
		return cmd_gen_key(param_types, params);

	case ENCRYPT_DECRYPT:
    TEE_ObjectHandle key;
    TEE_Result res = get_key(params[0].value.a, &key);
    res = cmd_do_crypto(param_types, params, key);
		return res;
	
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}