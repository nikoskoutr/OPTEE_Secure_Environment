#!/bin/bash

mkdir temp
cp $1 ./temp/
chmod +x ./temp/$1

tee_crypto crypto --digest --mode TEE_ALG_SHA256 --in_file ./temp/$1 --out_file ./temp/$1.sha256
optee_example_secure_storage get -f ./temp/$1.sig -i $1
tee_crypto crypto --verify --mode TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 --key_type RSA --ID $2 --in_file ./temp/$1.sha256 --out_file ./temp/$1.sig && ./temp/$1 || (echo Failed to authenticate && rm ./signature_database/$1.sig)

rm -rf ./temp/