#!/bin/bash

RSA_SIZE=2048

echo "Create Root key"
openssl genrsa -out prikey_${RSA_SIZE}.pem $RSA_SIZE
openssl rsa -in prikey_${RSA_SIZE}.pem -pubout -out pubkey_${RSA_SIZE}.pem
echo

for i in {0..15}
do
    echo "Create CSK key $i"
    openssl genrsa -out pricsk${i}_${RSA_SIZE}.pem $RSA_SIZE
    openssl rsa -in pricsk${i}_${RSA_SIZE}.pem -pubout -out pubcsk${i}_${RSA_SIZE}.pem
    echo ""
done
