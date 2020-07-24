# TEE Secure Environment

An OP-TEE based application that provides basic crypto primitives (AES, RSA, Hashing and Signing/Verifying) as well as utilization of the secure storage capabilities provided by OP-TEE.

An example usage can be found on enroll.sh and run.sh where these primitives are used to enroll an application by securely signing its hash and storing the signature in the secure storage. Afterwards, in the run.sh script, the application is re-hashed and verified against the signature stored within the secure storage.
