#!/bin/bash

mkdir temp

cp $1 ./temp/$1

tee_crypto crypto --digest --mode TEE_ALG_SHA256 --in_file ./temp/$1 --out_file ./temp/$1.sha256

tee_crypto crypto --sign --mode TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 --key_type RSA --ID $2 --in_file ./temp/$1.sha256 --out_file ./temp/$1.sig

optee_example_secure_storage store -f ./temp/$1.sig -i $1

rm -rf ./temp/
