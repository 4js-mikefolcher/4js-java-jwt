#!/bin/bash

#Create private key in PEM format
openssl genrsa -out private_key.pem 2048

#Convert private key to DER format
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt

#Generate public key in PEM format
openssl rsa -in private_key.pem -pubout -out public_key.pem

#Convert public key to DER format
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

