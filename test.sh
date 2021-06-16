#!/bin/sh
set -e

PYTHON=${PYTHON:-python3}

test -f masterlist-dsc.pem || sh  gen-csca-dsc.sh 

# JSON / CBOR / COSE / ZLIB / Base45
#
echo '{ "A" : "B" }' | ${PYTHON} hc1_sign.py |  ${PYTHON} hc1_verify.py
